import asyncio
import base64
import logging
from io import BytesIO
from math import trunc
from time import time
import os
import re
import binascii

from PIL import Image
from Crypto.Cipher.AES import (
	new as _new, block_size as _block_size, MODE_CBC as _MODE_CBC,
	MODE_ECB as _MODE_ECB
)
from Crypto.Util.Padding import pad as _pad

from aiocache import Cache as _Cache
from aiocache.serializers import NullSerializer as _NullSerializer
from aiohttp.client import (
	ClientSession as _ClientSession, ClientResponse as _ClientResponse
)

# 设置日志级别和格式
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 编译正则表达式,用于提取登录页面中的关键信息
LOGIN_INFO_REGEX = re.compile(r"\"pwdEncryptSalt\" value=\"(.*?)\".*?\"execution\" value=\"(.*?)\"")

# 工具函数

def b64encode(s, altchars=None):
	"""
	使用Base64编码字节类对象s并返回字节对象
	
	:param s: 要编码的字节类对象
	:param altchars: 可选的2字节字符串，用于替换'+'和'/'字符
	:return: Base64编码后的字节对象
	"""
	logger.debug(f"开始Base64编码, 输入长度: {len(s)}")
	encoded = binascii.b2a_base64(s, newline=False)
	if altchars is not None:
		assert len(altchars) == 2, repr(altchars)
		encoded = encoded.translate(bytes.maketrans(b'+/', altchars))
	logger.debug(f"Base64编码完成, 输出长度: {len(encoded)}")
	return encoded

def encrypt_aes(
	msg: str = "", key: bytes = b"", iv: bytes = b"",
	mode: int = _MODE_CBC, pad = lambda msg: msg.encode("utf-8")
):
	"""
	AES加密
	
	:param msg: 要加密的字符串
	:param key: 密钥（字节类型）
	:param iv: 初始化向量（字节类型）
	:param mode: 加密模式（CBC或ECB）
	:param pad: 填充函数，默认为UTF-8编码
	:return: Base64编码的加密字符串
	"""
	logger.debug(f"开始AES加密, 模式: {mode}, 消息长度: {len(msg)}")
	cipher = _new(key, mode) if mode == _MODE_ECB else _new(key, mode, iv)
	padded_msg = _pad(pad(msg), _block_size)
	encrypted = cipher.encrypt(padded_msg)
	result = b64encode(encrypted).decode("utf-8")
	logger.debug(f"AES加密完成, 结果长度: {len(result)}")
	return result

def solve_captcha(big_img = None, small_img = None, border: int = 24):
	"""
	滑块验证码求解器，基于归一化互相关
	
	:param big_img: 嵌入滑块的背景图像
	:param small_img: 带透明填充的垂直对齐滑块图像
	:param border: 滑块边框宽度。默认为8（超星），IDS推荐24
	:return: 滑块偏移量
	"""
	logger.debug(f"开始求解验证码, 大图尺寸: {big_img.size}, 小图尺寸: {small_img.size}, 边框宽度: {border}")
	big_img.load()
	small_img.load()
	
	# 获取滑块的有效区域
	# 创建LUT，只有当透明度为255时才保留该像素
 
	lut = [0] * 256
	lut[255] = 255

    # 获取滑块的有效区域
	if small_img.mode == 'RGBA':
		mask = small_img.split()[3].point(lut)  # 使用split()获取alpha通道
	else:
		raise ValueError("小图必须是带有透明度通道的RGBA模式。")
	
	bbox = mask.getbbox()
	if bbox is None:
		raise ValueError("未能找到有效的滑块区域，请检查输入的小图是否正确。")
	x_l, y_t, x_r, y_b = bbox
	x_l += border
	y_t += border
	x_r -= border
	y_b -= border
	
	# 提取模板并计算均值
	template = small_img.im.crop((x_l, y_t, x_r, y_b)).convert("L", 3)
	width_w = x_r - x_l
	len_w = width_w * (y_b - y_t)
	mean_t = sum(template) / len_w
	template = [v - mean_t for v in template]
	
	# 在背景图上滑动并计算相关性
	width_g = big_img.width - small_img.width + width_w - 1
	grayscale = big_img.im.convert("L", 3)
	cols_w = [
		sum(grayscale[y * big_img.width + x] for y in range(y_t, y_b))
		for x in range(x_l + 1, width_g + 1)
	]
	cols_w_l = iter(cols_w)
	cols_w_r = iter(cols_w)
	sum_w = sum(next(cols_w_r) for _ in range(width_w))
	ncc_max = x_max = 0
	
	for x in range(x_l + 1, width_g - width_w, 2):
		sum_w = (
			sum_w - next(cols_w_l) - next(cols_w_l) +
			next(cols_w_r) + next(cols_w_r)
		)
		mean_w = sum_w / len_w
		ncc = 0
		sum_ww = 0.000001
		for w, t in zip(grayscale.crop((
			x, y_t, x + width_w, y_b
		)), template):
			w -= mean_w
			ncc += w * t
			sum_ww += w * w
		ncc /= sum_ww
		if ncc > ncc_max:
			ncc_max = ncc
			x_max = x
	
	result = x_max - x_l - 1
	logger.debug(f"验证码求解完成, 计算得到的偏移量: {result}")
	return result

# 主要类定义

class _MockResponse:
	"""模拟响应类，用于缓存未命中时"""
	cookies, status = {}, 404

	async def json(self, *args, **kwargs):
		return {}

	async def read(self, *args, **kwargs):
		return b""

	async def text(self,  *args, **kwargs):
		return ""

class CachedSession:
	"""带缓存功能的aiohttp.ClientSession包装类"""
	__async_ctxmgr = headers = cookies = __session = __cache = None

	def __init__(
		self, headers: dict = None, cookies: dict = None,
		cache_enabled: bool = True
	):
		"""
		创建CachedSession实例
		
		:param headers: 默认请求头
		:param cookies: 默认cookies
		:param cache_enabled: 是否启用缓存
		"""
		if not self.__async_ctxmgr is None:
			return
		self.headers = headers or {}
		self.cookies = cookies or {}
		self.__session = _ClientSession()
		if cache_enabled:
			self.__cache = _Cache(
				_Cache.MEMORY, serializer = _NullSerializer()
			)
		logger.debug(f"CachedSession初始化完成, 缓存启用: {cache_enabled}")

	async def __aenter__(self):
		"""异步上下文管理器入口"""
		if not self.__async_ctxmgr is None:
			return self
		self.__async_ctxmgr = True
		await self.__session.__aenter__()
		logger.debug("CachedSession异步上下文管理器入口")
		return self

	async def __aexit__(self, *args, **kwargs):
		"""异步上下文管理器出口"""
		if self.__async_ctxmgr != True:
			return
		await self.__session.__aexit__(*args, **kwargs)
		self.__async_ctxmgr = False
		logger.debug("CachedSession异步上下文管理器出口")

	@property
	def session_cookies(self):
		"""获取会话cookies"""
		return self.__session.cookie_jar

	async def close(self):
		"""关闭会话"""
		await self.__aexit__(None, None, None)
		logger.debug("CachedSession已关闭")

	async def __cache_handler(
		self, func, ttl: int, *args, **kwargs
	) -> _ClientResponse:
		"""
		缓存处理器
		
		:param func: 要执行的函数
		:param ttl: 缓存时间（秒）
		:return: 客户端响应
		"""
		if not self.__cache or not ttl:
			return await func(*args, **kwargs)
		key = f"{func.__name__}{args}{kwargs.items()}"
		try:
			res = await self.__cache.get(key)
			logger.debug(f"缓存命中: {key}")
		except Exception:
			res = _MockResponse()
			logger.debug(f"缓存未命中: {key}")
		if not res:
			res = await func(*args, **kwargs)
			if res.status == 200 or res.status == 500:
				asyncio.create_task(self.__cache.set(key, res, ttl))
				logger.debug(f"设置缓存: {key}, TTL: {ttl}秒")
		return res

	async def get(
		self, url: str, params: dict = None, cookies: dict = None,
		headers: dict = None, ttl: int = 0, **kwargs
	) -> _ClientResponse:
		"""
		执行GET请求
		
		:param url: 请求URL
		:param params: 请求参数
		:param cookies: 请求cookies（覆盖现有cookies）
		:param headers: 请求头（覆盖现有请求头）
		:param ttl: 缓存时间（秒），默认为0（不缓存）
		:return: 客户端响应
		"""
		logger.debug(f"执行GET请求: {url}")
		res = await self.__cache_handler(
			self.__session.get, ttl, url = url, params = params,
			headers = headers if headers else self.headers,
			cookies = cookies if cookies else self.cookies,
			**kwargs
		)
		logger.debug(f"GET请求完成: {url}, 状态码: {res.status}")
		return res

	async def post(
		self, url: str, data: dict = None, cookies: dict = None,
		headers: dict = None, ttl: int = 0, **kwargs
	) -> _ClientResponse:
		"""
		执行POST请求
		
		:param url: 请求URL
		:param data: 请求数据
		:param cookies: 请求cookies（覆盖现有cookies）
		:param headers: 请求头（覆盖现有请求头）
		:param ttl: 缓存时间（秒），默认为0（不缓存）
		:return: 客户端响应
		"""
		logger.debug(f"执行POST请求: {url}")
		res = await self.__cache_handler(
			self.__session.post, ttl, url = url, data = data,
			headers = headers if headers else self.headers,
			cookies = cookies if cookies else self.cookies,
			**kwargs
		)
		logger.debug(f"POST请求完成: {url}, 状态码: {res.status}")
		return res

class IDSSession:
	"""处理西电统一身份认证系统的会话类"""

	def __init__(self, service: str = "", login_type: str = "userNameLogin", config: dict = {}):
		"""
		初始化IDS会话
		
		:param service: SSO服务重定向URL
		:param login_type: 登录类型,默认为用户名登录
		:param config: 额外配置
		"""
		logger.info(f"初始化IDSSession, service: {service}, login_type: {login_type}")
		self.__config = {
			"requests_headers": {
				"User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
			},
			"requests_cache_enabled": True
		}
		self.__config.update(config)
		self.__session = CachedSession(
			headers=self.__config["requests_headers"],
			cache_enabled=self.__config["requests_cache_enabled"]
		)
		self.__secrets = {"login_type": login_type}
		self.__service = service
		self.__async_ctxmgr = None
		logger.debug("IDSSession初始化完成")

	async def __aenter__(self):
		"""异步上下文管理器入口"""
		if self.__async_ctxmgr is None:
			self.__async_ctxmgr = True
			await self.__session.__aenter__()
		logger.debug("IDSSession异步上下文管理器入口")
		return self

	async def __aexit__(self, *args, **kwargs):
		"""异步上下文管理器出口"""
		if self.__async_ctxmgr:
			await self.__session.__aexit__(*args, **kwargs)
			self.__secrets = None
			self.__async_ctxmgr = False
		logger.debug("IDSSession异步上下文管理器出口")

	async def get(self, *args, **kwargs):
		"""封装session的get方法"""
		return await self.__session.get(*args, **kwargs)

	async def post(self, *args, **kwargs):
		"""封装session的post方法"""
		return await self.__session.post(*args, **kwargs)

	async def captcha_get_captcha(self):
		"""
		获取验证码图片
		
		:return: 包含大图和小图base64编码的字典
		"""
		logger.info("开始获取验证码")
		url = "https://ids.xidian.edu.cn/authserver/common/openSliderCaptcha.htl"
		params = {"_": f"{trunc(1000 * time())}"}
		res = await self.__session.get(url, params=params)
		logger.debug(f"验证码请求状态码: {res.status}")
		data = await res.json()
		logger.debug(f"获取到的验证码数据: {data}")
		return {
			"big_img_src": data["bigImage"],
			"small_img_src": data["smallImage"]
		}

	async def captcha_submit_captcha(self, captcha={"vcode": ""}):
		"""
		提交并验证验证码
		
		:param captcha: 包含验证码(滑块偏移量)的字典
		:return: 验证是否成功
		"""
		logger.info(f"提交验证码, vcode: {captcha['vcode']}")
		url = "https://ids.xidian.edu.cn/authserver/common/verifySliderCaptcha.htl"
		data = {"canvasLength": 280, "moveLength": captcha["vcode"]}
		res = await self.__session.post(url, data=data)
		logger.debug(f"验证码提交状态码: {res.status}")
		json_response = await res.json()
		logger.debug(f"验证码提交响应: {json_response}")
		return res.status == 200 and json_response["errorMsg"] == "success"

	async def login_prepare(self):
		"""
		准备登录IDS系统
		
		:return: 准备是否成功
		"""
		logger.info("准备登录IDS系统")
		url = "https://ids.xidian.edu.cn/authserver/login"
		params = {
			"service": self.__service,
			"type": self.__secrets["login_type"]
		}
		res = await self.__session.get(url, params=params)
		logger.debug(f"登录准备请求状态码: {res.status}")
		if res.status != 200:
			logger.error(f"登录准备失败，状态码: {res.status}")
			return False
		text = await res.text()
		logger.debug(f"登录页面内容: {text[:200]}...") # 只打印前200个字符
		match = LOGIN_INFO_REGEX.search(text)
		if not match:
			logger.error("无法从登录页面提取必要信息")
			return False
		self.__secrets.update({
			"login_salt": match[1],
			"login_execution": match[2]
		})
		logger.debug(f"提取的登录信息: {self.__secrets}")
		return True

	async def login_username_finish(self, account={"username": "", "password": ""}):
		"""
		完成用户名密码登录
		
		:param account: 包含用户名和密码的字典
		:return: 包含cookies和登录状态的字典
		"""
		logger.info(f"开始登录, 用户名: {account['username']}")
		password = encrypt_aes(
			msg=account["password"],
			key=self.__secrets["login_salt"].encode("utf-8"),
			iv=16 * b" ",
			pad=lambda msg: 64 * b" " + msg.encode("utf-8")
		)
		logger.debug("密码已加密")
		url = "https://ids.xidian.edu.cn/authserver/login"
		data = {
			"username": account["username"], "password": password,
			"captcha": "", "_eventId": "submit",
			"cllt": self.__secrets["login_type"],
			"dllt": "generalLogin", "lt": "", "rememberMe": True,
			"execution": self.__secrets["login_execution"]
		}
		params = {"service": self.__service}
		logger.debug(f"登录请求数据: {data}")
		res = await self.__session.post(url, data=data, params=params)
		logger.debug(f"登录请求状态码: {res.status}")
		ret = {"cookies": None, "logged_in": False}
		if res.status == 200:
			cookies = self.__session.session_cookies
			ret.update({
				"cookies": cookies,
				"logged_in": "CASTGC" in cookies.filter_cookies("https://ids.xidian.edu.cn/authserver")
			})
			logger.info(f"登录状态: {'成功' if ret['logged_in'] else '失败'}")
			logger.debug(f"获取到的cookies: {cookies}")
		else:
			logger.error(f"登录失败，状态码: {res.status}")
		return ret

# 主要功能函数

async def ids_get_cookies(username: str, password: str):
	"""
	获取IDS系统的cookies
	
	:param username: 用户名
	:param password: 密码
	:return: 登录成功后的cookies
	"""
	logger.info(f"开始获取IDS cookies, 用户名: {username}")
	async with IDSSession(service="http://payment.xidian.edu.cn/pages/caslogin.jsp") as ids:
		logger.debug("IDSSession创建成功")
		
		if not await ids.login_prepare():
			raise Exception("登录准备失败")
		logger.debug("登录准备完成")
		
		captcha = await ids.captcha_get_captcha()
		logger.debug(f"获取到的验证码数据: {captcha}")
		
		big_img = Image.open(BytesIO(base64.b64decode(captcha["big_img_src"])))
		small_img = Image.open(BytesIO(base64.b64decode(captcha["small_img_src"])))
		logger.debug(f"验证码图片大小 - 大图: {big_img.size}, 小图: {small_img.size}")
		
		vcode = solve_captcha(big_img, small_img, 24) * 280 // big_img.width
		logger.debug(f"计算得到的验证码vcode: {vcode}")
		
		if not await ids.captcha_submit_captcha({"vcode": vcode}):
			raise Exception("验证码提交失败")
		logger.debug("验证码提交成功")
		
		ret = await ids.login_username_finish({"username": username, "password": password})
		if not ret["logged_in"]:
			raise Exception("登录失败")
		logger.info("登录成功")
		
		cookies = ret["cookies"]
		logger.debug("获取到的所有cookies:")
		for cookie in cookies:
			logger.debug(f"  {cookie.key}: {cookie.value}")
		return cookies

async def get_payment_cookies(session, initial_cookies):
	"""
	获取支付系统的cookies
	
	:param session: 会话对象
	:param initial_cookies: 初始cookies
	:return: 支付系统的cookies
	"""
	logger.info("开始获取支付系统cookies")
	
	initial_url = "https://ids.xidian.edu.cn/authserver/login"
	params = {"service": "http://payment.xidian.edu.cn/pages/caslogin.jsp"}
	cookies_dict = {cookie.key: cookie.value for cookie in initial_cookies if cookie.key in ['route', 'JSESSIONID', 'org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE']}
	
	logger.debug(f"访问初始URL: {initial_url}")
	res = await session.get(initial_url, params=params, cookies=cookies_dict, allow_redirects=True)
	logger.debug(f"最终请求状态码: {res.status}")
	logger.debug(f"最终URL: {res.url}")
	
	all_cookies = session.session_cookies
	logger.debug("获取到的所有cookies:")
	for cookie in all_cookies:
		logger.debug(f"  {cookie.key}: {cookie.value}")
	
	jsessionid = next((cookie for cookie in all_cookies if cookie.key == 'JSESSIONID'), None)
	if jsessionid:
		return {'JSESSIONID': jsessionid.value}
	else:
		logger.error("未能获取JSESSIONID")
		return None

async def main():
	"""主函数"""
	username = os.environ.get("IDS_USERNAME")
	password = os.environ.get("IDS_PASSWORD")
	
	if not username or not password:
		username = input("请输入用户名: ")
		password = input("请输入密码: ")
	
	try:
		logger.info("开始主函数执行")
		initial_cookies = await ids_get_cookies(username, password)
		logger.info("获取到的初始 cookies:")
		for cookie in initial_cookies:
			logger.info(f"  {cookie.key}: {cookie.value}")
		
		async with CachedSession() as session:
			payment_cookies = await get_payment_cookies(session, initial_cookies)
		
		if payment_cookies:
			logger.info("获取到的支付系统 cookies:")
			for key, value in payment_cookies.items():
				logger.info(f"  {key}: {value}")
		else:
			logger.error("未能获取支付系统cookies")
	except Exception as e:
		logger.error(f"获取 cookies 时出错: {e}", exc_info=True)

if __name__ == "__main__":
	asyncio.run(main())
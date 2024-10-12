import requests

# 通用的请求头部设置
headers_template = {
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Cookie": ""  # 将在代码中动态设置
}

# 用户账户信息
account_data = {
    "p_Userid": "2008022302",    # 替换为实际的用户ID
    "p_Password": "123456",      # 替换为实际的密码
    "factorycode": "E003"
}

def get_liveid(jsessionid):
    """
    通过用户账号查询 liveid 和 addressid
    """
    url = "https://payment.xidian.edu.cn/NetWorkUI/checkUserInfo"
    headers = headers_template.copy()
    headers["Cookie"] = f"JSESSIONID={jsessionid}"
    
    response = requests.post(url, headers=headers, data=account_data)
    
    if response.status_code == 200:
        result = response.json()
        # 假设返回的 JSON 结构中含有 liveid 和 addressid
        if result.get("status") == "success":  # 根据实际返回数据结构调整条件
            liveid = result.get("liveid")
            addressid = result.get("addressid")
            return liveid, addressid
        else:
            print("获取 liveid 失败:", result.get("message"))
    else:
        print(f"请求失败，状态码: {response.status_code}")
    
    return None, None

def check_electricity(jsessionid, liveid, addressid):
    """
    使用获取的 liveid 和 addressid 查询电费
    """
    url = "https://payment.xidian.edu.cn/NetWorkUI/checkPayelec"
    headers = headers_template.copy()
    headers["Cookie"] = f"JSESSIONID={jsessionid}"
    
    data = {
        "liveid": liveid,
        "addressid": addressid,
        "payAmt": "a",  # payAmt 值根据需求调整
        "factorycode": "E003"
    }
    
    response = requests.post(url, headers=headers, data=data)
    
    if response.status_code == 200:
        print("查询电费结果:", response.text)
    else:
        print(f"电费查询请求失败，状态码: {response.status_code}")

def main():
    # 请输入 JSESSIONID
    jsessionid = input("请输入 JSESSIONID: ")
    
    # Step 1: 获取 liveid 和 addressid
    liveid, addressid = get_liveid(jsessionid)
    
    if liveid and addressid:
        # Step 2: 查询电费
        check_electricity(jsessionid, liveid, addressid)
    else:
        print("无法获取 liveid 或 addressid")

if __name__ == "__main__":
    main()

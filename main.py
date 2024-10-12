import requests

headers_template = {
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Cookie": ""  # 将在代码中动态设置
}

# 用户账户信息，这个之后看看有什么数据库可以改
account_data = {
    "p_Userid": "2008022302",    
    "p_Password": "123456",      # 这个好像可以不用换
    "factorycode": "E003"
}

def get_liveid_and_addressid(jsessionid):
    """
    通过用户账号查询 liveid 和 addressid
    """
    url = "https://payment.xidian.edu.cn/NetWorkUI/checkUserInfo"
    headers = headers_template.copy()
    headers["Cookie"] = f"JSESSIONID={jsessionid}"
    
    response = requests.post(url, headers=headers, data=account_data)
    
    if response.status_code == 200:
        result = response.json()
        if result.get("returncode") == "SUCCESS":  # TODO: 记得添加FAILED等情况的判定
            liveid = result.get("liveid")
            room_list = result.get("roomList", [])
            if room_list:
                # 提取 roomList 中的 addressid，目前观察应该都是在@符号前面的
                addressid = room_list[0].split("@")[0]
                return liveid, addressid
            else:
                print("未找到 roomList，无法获取 addressid")
        else:
            print("获取 liveid 失败:", result.get("returnmsg"))
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
        "payAmt": "草",  # payAmt 只要不是合法字符就能触发报错返回电量
        "factorycode": "E003"
    }
    
    response = requests.post(url, headers=headers, data=data)
    
    if response.status_code == 200:
        result = response.json()
        # 提取 RemainQty
        try:
            remain_qty = result["rtmeterInfo"]["Result"]["Meter"]["RemainQty"]
            print(f"剩余电量: {remain_qty} 度")
        except KeyError:
            print("无法提取 RemainQty，响应数据结构可能已更改")
    else:
        print(f"电费查询请求失败，状态码: {response.status_code}")
        
        
def main():
    jsessionid = input("请输入 JSESSIONID: ")
    
    # Step 1: 获取 liveid 和 addressid
    liveid, addressid = get_liveid_and_addressid(jsessionid)
    
    if liveid and addressid:
        # Step 2: 根据 liveid 和 addressid 查询电费
        check_electricity(jsessionid, liveid, addressid)
    else:
        print("无法获取 liveid 或 addressid")

if __name__ == "__main__":
    main()

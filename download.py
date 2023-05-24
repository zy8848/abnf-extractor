import urllib.request
import os
from multiprocessing.pool import ThreadPool

# 指定要下载的RFC文档编号范围
start_number = 9400
end_number = 9999

# 指定保存文件的目录
save_dir = "input_abnf"

# 如果目录不存在，则创建目录
if not os.path.exists(save_dir):
    os.makedirs(save_dir)

# 定义下载函数
def download_rfc(rfc_number):
    # 构造URL地址
    url = f"https://www.rfc-editor.org/rfc/rfc{rfc_number}.txt"

    # 指定保存文件的路径
    save_path = os.path.join(save_dir, f"rfc{rfc_number}.txt")

    # 尝试下载文件并保存到指定目录，如果下载失败则返回None
    try:
        urllib.request.urlretrieve(url, save_path)
        print(f"RFC{rfc_number}已经下载到{save_path}")
        return rfc_number
    except:
        print(f"下载RFC{rfc_number}时出错，跳过该文档")
        return None

# 使用线程池进行并行下载
with ThreadPool(processes=50) as pool:
    # 循环添加每个RFC文档的下载任务到线程池中
    tasks = [pool.apply_async(download_rfc, args=(rfc_number,)) for rfc_number in range(start_number, end_number + 1)]

    # 等待所有任务完成，并收集下载成功的RFC文档编号
    downloaded_rfcs = [task.get() for task in tasks if task.get() is not None]

# 打印所有RFC文档下载完成的提示信息
print("所有RFC文档已经下载完成！")

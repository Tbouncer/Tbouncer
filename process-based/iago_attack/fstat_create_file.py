import struct

def create_test_file(filename, nlibs, libs):
    """
    创建一个符合结构体定义的测试文件

    :param filename: 文件名
    :param nlibs: 库数量 (uint32)
    :param libs: 库名称列表，每个名称为字符串
    """
    with open(filename, "wb") as f:
        # 写入 nlibs (uint32)
        f.write(struct.pack("I", nlibs))
        
        # 写入库名称，每个库名以 '\0' 结尾
        for lib in libs:
            f.write(lib.encode('utf-8') + b'\0')

# 示例用法
if __name__ == "__main__":
    filename = "testfile"
    nlibs = 3
    libs = ["lib1", "lib2", "lib3"]  # 库名称列表

    create_test_file(filename, nlibs, libs)
    print(f"Test file '{filename}' created successfully.")


import re
import os

def modify_c_file(file_path):
    # 提取文件名（不含路径和扩展名）
    file_name_without_extension = os.path.splitext(os.path.basename(file_path))[0]

    with open(file_path, 'r') as file:
        code = file.readlines()

    # Step 1: Identify the function assigned to .test or .test_all
    test_function_name = None
    for line in code:
        match = re.search(r'\.(test|test_all)\s*=\s*(\w+)', line)
        if match:
            test_function_name = match.group(2)  # 提取函数名
            break

    if not test_function_name:
        print("No function assigned to `.test` or `.test_all` found.")
        return

    print(f"Function assigned to .test or .test_all: {test_function_name}")

    # Step 2: Locate the function and modify its content
    modified_code = []
    in_function = False
    brace_level = 0
    end_append = False

    for line in code:
        if not in_function:
            # 搜索目标函数定义
            match = re.match(rf'\s*void\s+{test_function_name}\s*\(.*\)\s*', line)
            if match:
                in_function = True
                modified_code.append(line)
                continue
        else:
            if line.strip() == "{":
                brace_level += 1
                modified_code.append(line)
                # 在函数开始位置写入文件名去掉 `.c`
                modified_code.append(f'    write_coordination_file("{file_name_without_extension}");\n')
                continue

            # 跟踪大括号找到函数的结束位置
            brace_level += line.count("{") - line.count("}")
            if brace_level == 0:
                # 在函数结束位置写入文件名去掉 `.c`
                if not end_append:
                    end_append = True
                    modified_code.append(f'    write_coordination_file("0");\n')
                modified_code.append(line)
                in_function = False
                continue

        modified_code.append(line)

    # Step 3: 写回修改后的代码
    with open(file_path, 'w') as file:
        file.writelines(modified_code)

    print(f"Modified function `{test_function_name}` in file `{file_path}`.")


def modify_all_c_files_in_directory(directory_path):
    # 检查目录是否存在
    if not os.path.isdir(directory_path):
        print(f"Error: Directory {directory_path} does not exist.")
        return

    # 遍历目录中的所有 .c 文件
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.c'):
                file_path = os.path.join(root, file)
                print(f"Processing file: {file_path}")
                modify_c_file(file_path)


# Example usage:
directory_path = './c_files'  # 替换为你的目录路径
modify_all_c_files_in_directory(directory_path)
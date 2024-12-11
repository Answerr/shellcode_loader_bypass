def xor_encrypt_decrypt(input_file, output_file, key=0x5A):  
    """  
    使用 XOR 加密或解密二进制文件。  
    
    :param input_file: 输入文件路径  
    :param output_file: 输出文件路径  
    :param key: XOR 密钥，默认为 0x5A  
    """  
    try:  
        # 打开输入文件（以二进制模式读取）  
        with open(input_file, 'rb') as f_in:  
            data = f_in.read()  
        
        # 对数据进行 XOR 操作  
        encrypted_data = bytearray([byte ^ key for byte in data])  
        
        # 将加密/解密后的数据写入输出文件  
        with open(output_file, 'wb') as f_out:  
            f_out.write(encrypted_data)  
        
        print(f"文件已成功处理，输出文件为: {output_file}")  
    except FileNotFoundError:  
        print(f"错误: 找不到文件 {input_file}")  
    except Exception as e:  
        print(f"发生错误: {e}")  

# 示例用法  
if __name__ == "__main__":  
    input_file = "input.bin"  # 输入文件路径  
    output_file = "output.bin"  # 输出文件路径  
    xor_encrypt_decrypt(input_file, output_file)  
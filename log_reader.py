def read_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()

        return lines

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return None
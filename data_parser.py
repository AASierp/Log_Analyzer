
def read_and_clean_data(file_path):
    cleaned_data = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                words = line.strip()
                if not words:
                    continue
                clean_words = words.split("\t")
                cleaned_data.append(clean_words)
    except FileNotFoundError:
        print(f"Error - {file_path} not found.")
        return []
    except Exception as e:
        print(f"Error - Unexpected runtime error - {e}")
    return cleaned_data

def model_data(cleaned_data):
    modeled_data = []
    
    for field in cleaned_data:
        
        model = {}
        model["Timestamp"] = field[0] if len(field) > 0 else "Unknown"
        model["AUTH"] = field[1] if len(field) > 1 else "Unknown"
        model["User"] = field[2].replace("user=", "") if len(field) > 2 else "Unknown"
        model["IP"] = field[3].replace("ip=", "") if len(field) > 3 else "Unknown"
        model["Message"] = " ".join(field[4:]).replace("message=", "") if len(field) > 4 else "Unknown"
        modeled_data.append(model)
    
    # with open("test_output/test.txt", "w") as file:
    #     for record in modeled_data:
    #         file.write(str(record) + "\n")
                
    return modeled_data


        
            
            
        


                

    

    
    


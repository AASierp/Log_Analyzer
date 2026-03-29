
def read_and_clean_data(file_path):
    cleaned_data = []
    with open(file_path, "r") as file:
        for line in file:
            words = line.strip()
            if not words:
                continue
            clean_words = words.split("\t")
            cleaned_data.append(clean_words)
    return cleaned_data

def model_data(cleaned_data):
    modeled_data = []
    
    for field in cleaned_data:
        
        model = {}
        model["Timestamp"] = field[0]
        model["AUTH"] = field[1]
        model["User"] = field[2].replace("user=", "")
        model["IP"] = field[3].replace("ip=", "")
        model["Message"] = " ".join(field[4:]).replace("message=", "")
        modeled_data.append(model)
    
    
    with open("test_output/test.txt", "w") as file:
        for record in modeled_data:
            
            file.write(str(record) + "\n")
                
    return modeled_data


        
            
            
        


                

    

    
    


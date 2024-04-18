import string

def frequencyAnalysis(ciphertext):
    frequencies = {}
    totalChars = 0
    
    for char in ciphertext:
        if char != " ":
            totalChars += 1
            if char in frequencies:
                frequencies[char] += 1
            else:
                frequencies[char] = 1
            
    for char in frequencies:
        percentage = (frequencies[char] / totalChars) * 100
        frequencies[char] = (frequencies[char], percentage)
        
    return frequencies

def main():
    ciphertext = input("Enter the ciphertext: ")
    frequencies = frequencyAnalysis(ciphertext)

    print("\nFrequency Analysis:")
    for char, (count, percentage) in frequencies.items():
        print(f"'{char}' appears {count} times, which is {percentage:.2f}% of the total")

if __name__ == "__main__":
    main()
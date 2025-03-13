# yara-rule-generator
Automates the creation of yara rules and files to help in threat detection

- As you can see from this image, it asks the user what metadata the user wants to add
- It runs recursively to allow the user to add as much data needed
- The user is required to add at least 1 metadata for the yara file to work
- Addable metadata includes author, description of rule, last date modified and threat level

![Image](https://github.com/user-attachments/assets/762bfe6a-9709-4a87-ad1c-e30c02e5310c)


- The image below shows the script asking the user if they would like to use the yara file to look for strings within the malicious files
- The user is then required to give a variable name
- The user is also prompted to remember the variable name to be used later on
- This part of the script runs recursively to allow the user to add as many strings as they want

![Image](https://github.com/user-attachments/assets/3e02b7e7-0939-40ab-bdac-9f76a0ec4234)


- The image below asks the user about what type of rule they would like to use on those strings in the condition portion
- This confirms if the user wants either of the strings or both of them in the file

![Image](https://github.com/user-attachments/assets/2e6f39fd-b47f-4347-8add-3a3cbb8ebd27)

- This image shows the script asking the user if there is a specific file type to look for
- The file headers of exe,elf and zip are already hard coded into the script such that any one of those file types would be detected in a yara script


![Image](https://github.com/user-attachments/assets/85ad5edd-f172-4041-b734-4d6070e1fcbb)

- This function allows the user to use the yara file to look for possibly malicious files in any directory and any file that meets the requirements specified by the user will be picked up
  
![Image](https://github.com/user-attachments/assets/1b539a2c-7ace-4c25-9452-ca0b58d1a65b)

- The final image shows the file generated by the script
- 
![Image](https://github.com/user-attachments/assets/52efde7a-be48-4453-bcb9-9e35162ec552)



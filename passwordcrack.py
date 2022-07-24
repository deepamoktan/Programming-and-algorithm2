import hashlib
import random
import pyautogui


chars = "abcdefghijklmnopqrstuvwxyz1234567890"
chars_list = list(chars)

password = pyautogui.password("Enter A Password: ")
guess_password = ""

while(guess_password != password):
	guess_password = random.choices(chars_list, k=len(password))
	print("<==========="+ str(guess_password) + "===========>")

	if(guess_password == list(password)):
		print("Your Password Is: " + "".join(guess_password))
		print("\n")

		print("1. Generate sha256 hash: ")
		print("2. SHA256 hash password crack to plain text: ")
		print("3. Exit Program: ")

		while True:
			user_choice = input("Choose a option: ")

			if user_choice == "1":
				input_user = input("Enter your username: ")
				input_passwd = input("Enter your password: ")

				hashed = hashlib.sha256(input_passwd.encode('utf-8')).hexdigest()
				print("The hashed password is: ", hashed)

			if user_choice == "2":
				flag = 0

				pass_hash = input("Enter sha256 hash: ")
				wordlist = input("File name: ")

				try:
					pass_file = open(wordlist, "r")
				except:
					print("No file found")
					quit()

				for word in pass_file:

					enc_wrd = word.encode('utf-8')
					digest = hashlib.sha256(enc_wrd.strip()).hexdigest()

					print(word)
					print(digest)
					print(pass_hash)

					if digest == pass_hash:
						print("Password found")
						print("Password is " + word)
						flag = 1
						break

				if flag == 0:
					print("Password is not in the list")


			elif user_choice == "3":
				print("Quitting The Program....")
				break

			else:
				print("Please Choose a correct option")

		input()
		break

	
import random

class New_Banner(object):
	"""Gives New Banner"""
	def __init__(self):
		pass

	def new(self):
			banner1 = """

▄▄▄█████▓ ██░ ██ ▓█████   ██████ ▓█████  █    ██   ██████ 
▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ ▒██    ▒ ▓█   ▀  ██  ▓██▒▒██    ▒ 
▒ ▓██░ ▒░▒██▀▀██░▒███   ░ ▓██▄   ▒███   ▓██  ▒██░░ ▓██▄   
░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄   ▒   ██▒▒▓█  ▄ ▓▓█  ░██░  ▒   ██▒
  ▒██▒ ░ ░▓█▒░██▓░▒████▒▒██████▒▒░▒████▒▒▒█████▓ ▒██████▒▒
  ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░
    ░     ▒ ░▒░ ░ ░ ░  ░░ ░▒  ░ ░ ░ ░  ░░░▒░ ░ ░ ░ ░▒  ░ ░
  ░       ░  ░░ ░   ░   ░  ░  ░     ░    ░░░ ░ ░ ░  ░  ░  
          ░  ░  ░   ░  ░      ░     ░  ░   ░           ░  
                                                          
                      
	"""
			banner2 = """


    ███        ▄█    █▄       ▄████████    ▄████████    ▄████████ ███    █▄     ▄████████ 
▀█████████▄   ███    ███     ███    ███   ███    ███   ███    ███ ███    ███   ███    ███ 
   ▀███▀▀██   ███    ███     ███    █▀    ███    █▀    ███    █▀  ███    ███   ███    █▀  
    ███   ▀  ▄███▄▄▄▄███▄▄  ▄███▄▄▄       ███         ▄███▄▄▄     ███    ███   ███        
    ███     ▀▀███▀▀▀▀███▀  ▀▀███▀▀▀     ▀███████████ ▀▀███▀▀▀     ███    ███ ▀███████████ 
    ███       ███    ███     ███    █▄           ███   ███    █▄  ███    ███          ███ 
    ███       ███    ███     ███    ███    ▄█    ███   ███    ███ ███    ███    ▄█    ███ 
   ▄████▀     ███    █▀      ██████████  ▄████████▀    ██████████ ████████▀   ▄████████▀  
                                                                                          


	"""

			banner3 = """


 ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌
 ▀▀▀▀█░█▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ 
     ▐░▌     ▐░▌       ▐░▌▐░▌          ▐░▌          ▐░▌          ▐░▌       ▐░▌▐░▌          
     ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ 
     ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌
     ▐░▌     ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌ ▀▀▀▀▀▀▀▀▀█░▌
     ▐░▌     ▐░▌       ▐░▌▐░▌                    ▐░▌▐░▌          ▐░▌       ▐░▌          ▐░▌
     ▐░▌     ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌ ▄▄▄▄▄▄▄▄▄█░▌
     ▐░▌     ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
      ▀       ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 
                                                                                           

    """

			banners = [banner1, banner2, banner3]
			return random.choice(banners)
		
if __name__ == '__main__':
	b = New_Banner()
	print(b.new())
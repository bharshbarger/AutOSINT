#!/usr/bin/env python

try:
	import sqlite3
except ImportError as e:
	raise ImportError('Error importing %s' % e)

class SetupDatabase():
	def __init__(self):
		
		#vars
		self.autOSINTDB = 'AutOSINT.db'

	def createdatabase(self):

		# Database Connection

		try:
			connection = sqlite3.connect(self.autOSINTDB)
			c = connection.cursor()

			#Create table
			c.execute('''CREATE TABLE client(
				ID INTEGER PRIMARY KEY,
				name text, 
				domain text, 
				Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
				UNIQUE(name))''')

			c.execute('''CREATE TABLE whois(
				ID INTEGER PRIMARY KEY,
				contact text,
				client_id integer,
				FOREIGN KEY(client_id) REFERENCES client(ID)''')
			
			c.execute('''CREATE TABLE users(
				ID INTEGER PRIMARY KEY,
				name text,
				email text,
				username text,
				client_id integer,
				FOREIGN KEY(client_id) REFERENCES client(ID)''')

			c.execute('''CREATE TABLE creds(
				ID INTEGER PRIMARY KEY,
				username text,
				hash text,
				plain text,
				client_id integer,
				FOREIGN KEY(client_id) REFERENCES client(ID)''')



			# Commit and close connection to database
			connection.commit()
			connection.close()

		except sqlite3.Error as e:
			print(" [-] Database Error: %s" % e.args[0])

def main():
	createDb = Database()
	createDb.createdatabase()


if __name__ == '__main__':
	main()

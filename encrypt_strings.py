import random

def encrypt(plain, key):
  random.seed()
  
  encrypted = hex(random.randint(16, 240))[2:].upper()
  if len(encrypted) < 2:
	  encrypted = '0' + encrypted
  
  for i in range(len(plain)):
    sum = ord(plain[i]) + int(encrypted[i*2:], 16)
    if sum > 255:
      sum = sum - 255
    j = i % len(key)
    appnd = hex(sum ^ ord(key[j]))[2:]
    
    if len(appnd) < 2:
		appnd = '0' + appnd
    encrypted = encrypted + appnd.upper()

  return encrypted

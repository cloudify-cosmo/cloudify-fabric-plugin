import sys


def write():
    try:
        file = with open('c:\\users\\administrator\\desktop\\'
                         'python-succes.txt', 'a')
        file.write('success!!')
    except:
        print('Something went wrong! Can\'t tell what?')
        sys.exit(0)

write()

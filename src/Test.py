from utils.FileUtils import FileUtils
import ast

test = FileUtils.open_ini_file('./conf/test.ini')
list_value = ast.literal_eval(test.get('FOO', 'car'))

print(type(list_value))
print(list_value)
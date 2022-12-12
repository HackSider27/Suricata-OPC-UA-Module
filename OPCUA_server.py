from opcua import Server
from random import randint
import datetime
import time
from opcua import ua

server = Server()

url = "opc.tcp://192.168.52.130:4840"
server.set_endpoint(url)

name = "OPCUA_SERVER"
addspace = server.register_namespace(name)

node = server.get_objects_node()

Param = node.add_object(addspace, "Parameters")

Temp = Param.add_variable(addspace, "Temperature", 0)
Press = Param.add_variable(addspace, "Pressure", 0)
Time = Param.add_variable(addspace, "Time", 0)

Temp.set_writable()
Press.set_writable()
Time.set_writable()

server.start()
print("Server started at {}".format(url))

while True:
    try:
        Temperature = randint(10, 50)
        Pressure = randint(200, 999)
        T = datetime.datetime.now()

        print(Temperature, Pressure, T)

        Temp.set_value(Temperature)
        Press.set_value(Pressure)
        Time.set_value(T)

        time.sleep(2)
    except KeyboardInterrupt:
        print("Closing connection...")
        break
print()
server.stop()
print("Server stopped")
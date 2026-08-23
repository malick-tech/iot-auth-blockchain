import paho.mqtt.client as mqtt,time
got=[]
def oc(c,u,f,rc,p=None):
    c.subscribe("iot/#",1)
    print("SUB OK rc="+str(rc),flush=True)
def om(c,u,m):
    got.append(m.topic)
    print("GOT:"+m.topic,flush=True)
cl=mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
cl.on_connect=oc
cl.on_message=om
cl.connect("mosquitto",1883)
cl.loop_start()
time.sleep(10)
print("TOTAL:"+str(len(got)),flush=True)
cl.loop_stop()

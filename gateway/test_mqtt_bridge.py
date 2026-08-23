import paho.mqtt.client as mqtt, time, json

received = []

def on_conn(c, u, f, rc, p=None):
    print("CONNECTED rc=" + str(rc))
    c.subscribe("iot/+/enrollment/first-contact/request", 1)
    print("SUBSCRIBED")

def on_msg(c, u, m):
    received.append(m.topic)
    print("RECEIVED: " + m.topic)

cl = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
cl.on_connect = on_conn
cl.on_message = on_msg
cl.connect("mosquitto", 1883)
cl.loop_start()
time.sleep(2)
cl.publish("iot/IOT-TEMP-001/enrollment/first-contact/request", json.dumps({"test": 1}), qos=1)
print("PUBLISHED")
time.sleep(3)
print("TOTAL RECEIVED: " + str(len(received)))
cl.loop_stop()

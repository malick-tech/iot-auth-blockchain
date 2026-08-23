import paho.mqtt.client as mqtt, time, json, sys

received = []
def on_conn(c, u, f, rc, p=None):
    c.subscribe("iot/WIN-TEST/enrollment/first-contact/request", 1)
def on_msg(c, u, m):
    received.append(m.topic)
    print("BRIDGE RECEIVED: " + m.topic, flush=True)

cl = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
cl.on_connect = on_conn
cl.on_message = on_msg
cl.connect("mosquitto", 1883)
cl.loop_start()
time.sleep(8)
print("BRIDGE TOTAL: " + str(len(received)), flush=True)
cl.loop_stop()

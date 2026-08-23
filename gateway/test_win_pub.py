import paho.mqtt.client as mqtt, time, json
cl = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
cl.connect("localhost", 1883)
cl.loop_start()
time.sleep(1)
r = cl.publish("iot/WIN-TEST/enrollment/first-contact/request", json.dumps({"from":"windows"}), qos=1)
print("Windows pub rc=" + str(r.rc))
time.sleep(1)
cl.loop_stop()

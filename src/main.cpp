
#include <print>

#include <kxx/mqtt/client.hpp>
#include <kxx/mqtt/format.hpp> // for using std::println and std::format on mqtt settings and status codes

int main(){

  // Assumes you have a basic MQTT setup running on port 1883 without username and password

  // Create Client
  kxx::mqtt::MqttClient client{"kxx_mqtt_client_example"};

  // handle messages received
  client.set_message_handler(
    [](const std::string& topic, const std::vector<uint8_t>& payload, kxx::mqtt::QoS qos, bool retain) {
      std::string message(std::from_range, payload);
      std::println(
          "on_message QOS_0 with topic: {}, QoS: {}, retain: {}, message: {}", 
          topic, qos, retain, message
        );
    }
  );

	if(auto ok = client.connect("localhost", 1883); ok) {

    // subscribe to some test topics
		client.subscribe("kxx_mqtt_test/qos0", kxx::mqtt::QOS_0);
		client.subscribe("kxx_mqtt_test/qos1", kxx::mqtt::QOS_1);
		client.subscribe("kxx_mqtt_test/qos2", kxx::mqtt::QOS_2);


    // send some test messages
		for (int i = 0; i < 5; i++) {
			std::string msg = std::format("Message #{}", i);
			client.publish("kxx_mqtt_test/qos0", msg, kxx::mqtt::QOS_0);
			client.publish("kxx_mqtt_test/qos1", msg, kxx::mqtt::QOS_1);
			client.publish("kxx_mqtt_test/qos2", msg, kxx::mqtt::QOS_2);

			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		}
	}else{
    std::println("Could not connect: {}", ok.error());
  }

}

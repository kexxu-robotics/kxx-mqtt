
#include <kxx/mqtt/client.hpp>

int main(){

  // Publisher
  kxx::mqtt::MqttClient publisher("publisher_main");
  if (publisher.connect("localhost", 1883)) {
    for (int i = 0; i < 5; i++) {
      std::string msg = "Message #" + std::to_string(i);
      publisher.publish("kxx_mqtt_test/data", msg, kxx::mqtt::QOS_1);
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
  }

}

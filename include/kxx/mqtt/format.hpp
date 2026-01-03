#pragma once

#include <kxx/mqtt/packet.hpp>

#include <format>
#include <string_view>

// Formatters , to use with std::format and std::println etc.
namespace std {

  template <>
  struct std::formatter<kxx::mqtt::ProtocolVersion> : std::formatter<std::string_view> {
    auto format(kxx::mqtt::ProtocolVersion p, format_context& ctx) const {
      return std::formatter<std::string_view>::format(kxx::mqtt::to_string(p), ctx);
    }
  };

  template <>
  struct std::formatter<kxx::mqtt::PacketType> : std::formatter<std::string_view> {
    auto format(kxx::mqtt::PacketType p, format_context& ctx) const {
      return std::formatter<std::string_view>::format(kxx::mqtt::to_string(p), ctx);
    }
  };

  template <>
  struct std::formatter<kxx::mqtt::QoS> : std::formatter<std::string_view> {
    auto format(kxx::mqtt::QoS q, format_context& ctx) const {
      return std::formatter<std::string_view>::format(kxx::mqtt::to_string(q), ctx);
    }
  };

  template <>
  struct std::formatter<kxx::mqtt::PropertyId> : std::formatter<std::string_view> {
    auto format(kxx::mqtt::PropertyId q, format_context& ctx) const {
      return std::formatter<std::string_view>::format(kxx::mqtt::to_string(q), ctx);
    }
  };

  template <>
  struct std::formatter<kxx::mqtt::ReasonCode> : std::formatter<std::string_view> {
    auto format(kxx::mqtt::ReasonCode q, format_context& ctx) const {
      return std::formatter<std::string_view>::format(kxx::mqtt::to_string(q), ctx);
    }
  };

}

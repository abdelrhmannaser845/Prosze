#pragma once

#include <functional>
#include <string>

struct ProszeProxyConfig
{
    std::string listen_host = "127.0.0.1";
    unsigned short listen_port = 8787;
    std::string upstream;
    unsigned timeout_seconds = 60;
};

using ProszeProxyTransform = std::function<std::string(const std::string&)>;

int run_prosze_proxy(const ProszeProxyConfig& config,
                     ProszeProxyTransform redact,
                     ProszeProxyTransform restore);

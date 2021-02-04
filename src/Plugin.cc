#include "Plugin.h"
#include "Dpdk.h"
#include <iosource/Component.h>

namespace plugin { namespace Zeek_Dpdk { Plugin plugin; } }

using namespace plugin::Zeek_Dpdk;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::iosource::PktSrcComponent("DpdkReader", "dpdk", ::iosource::PktSrcComponent::LIVE, ::iosource::pktsrc::DpdkSource::Instantiate));
	plugin::Configuration config;
	config.name = "Zeek::Dpdk";
	config.description = "Packet acquisition via Dpdk";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
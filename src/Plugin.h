
#ifndef ZEEK_PLUGIN_ZEEK_DPDK
#define ZEEK_PLUGIN_ZEEK_DPDK

#include <plugin/Plugin.h>

namespace plugin {
namespace Zeek_Dpdk {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from zeek::plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}
#endif
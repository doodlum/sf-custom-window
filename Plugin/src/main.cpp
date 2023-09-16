#include "DKUtil/Hook.hpp"

#include <SimpleIni.h>

DLLEXPORT constinit auto SFSEPlugin_Version = []() noexcept {
	SFSE::PluginVersionData data{};

	data.PluginVersion(Plugin::Version);
	data.PluginName(Plugin::NAME);
	data.AuthorName(Plugin::AUTHOR);
	data.UsesSigScanning(true);
	//data.UsesAddressLibrary(true);
	data.HasNoStructUse(true);
	//data.IsLayoutDependent(true);
	data.CompatibleVersions({ SFSE::RUNTIME_LATEST });

	return data;
}();

struct Unk_SetForegroundWindow
{
	static BOOL __stdcall thunk(HWND hWnd)
	{
		auto hIcon = LoadImage(NULL, L"Data\\SFSE\\Plugins\\CustomWindow.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
		if (hIcon) {
			INFO("Replacing window icon");
			SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
			SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
		} else {
			INFO("Could not load icon");
		}

		CSimpleIniA ini;
		ini.SetUnicode();
		ini.LoadFile(L"Data\\SFSE\\Plugins\\CustomWindow.ini");

		if (auto title = ini.GetValue("Settings", "Title")) {
			INFO("Replacing window title");
			SetWindowTextA(hWnd, title);
		} else {
			INFO("Could not find INI string for window title");
		}
		return func(hWnd);
	}
	static inline REL::Relocation<decltype(thunk)> func;
};

namespace stl
{
	template <class T>
	void write_thunk_call6F15(std::uintptr_t a_src)
	{
		SFSE::AllocTrampoline(14);
		auto& trampoline = SFSE::GetTrampoline();
		T::func = *reinterpret_cast<std::uintptr_t*>(trampoline.write_call<6>(a_src, T::thunk));
	}
}

DLLEXPORT bool SFSEAPI SFSEPlugin_Load(const SFSE::LoadInterface* a_sfse)
{
#ifndef NDEBUG
	while (!IsDebuggerPresent()) {
		Sleep(100);
	}
#endif

	SFSE::Init(a_sfse, false);

	DKUtil::Logger::Init(Plugin::NAME, std::to_string(Plugin::Version));

	INFO("{} v{} loaded", Plugin::NAME, Plugin::Version);

	SFSE::AllocTrampoline(14);

	{
		const auto scan = static_cast<uint8_t*>(dku::Hook::Assembly::search_pattern<"FF 15 ?? ?? ?? ?? 48 8B 8E B0 00 00 00 FF 15 ?? ?? ?? ?? 44 8B 4E 04">());
		if (!scan) {
			ERROR("Failed to find SetForegroundWindow!")
		}
		stl::write_thunk_call6F15<Unk_SetForegroundWindow>(AsAddress(scan));
		INFO("Found SetForegroundWindow at {:X}", AsAddress(scan) - dku::Hook::Module::get().base() + 0x140000000);
	}

	return true;
}

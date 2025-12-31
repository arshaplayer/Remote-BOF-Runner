x64:
	load "Bin/loader.x64.o"
		make pic +gofirst +optimize

		fixbss "getBSS"

		dfr "resolve" "ror13"
		mergelib "./Libraries/LibIPC/libipc.x64.zip"
		mergelib "./Libraries/LibTCG/libtcg.x64.zip"

		push $OBJECT
			make object
			
			remap "__imp_BeaconOutput" "__imp_BEACON$BeaconOutput"
			remap "__imp_BeaconPrintf" "__imp_BEACON$BeaconPrintf"

			remap "__imp_BeaconDataExtract" "__imp_BEACON$BeaconDataExtract"
			remap "__imp_BeaconDataParse"   "__imp_BEACON$BeaconDataParse"
			remap "__imp_BeaconDataPtr"     "__imp_BEACON$BeaconDataPtr"
			remap "__imp_BeaconDataInt"     "__imp_BEACON$BeaconDataInt"
			remap "__imp_BeaconDataShort"   "__imp_BEACON$BeaconDataShort"
			remap "__imp_BeaconDataLength"  "__imp_BEACON$BeaconDataLength"

			remap "__imp_GetModuleHandleA" "__imp_KERNEL32$GetModuleHandleA"

			remap "memcpy" "__imp_MSVCRT$memcpy"
			remap "memset" "__imp_MSVCRT$memset"
			
			export
			link "bof"

		load %BOF_ARGS
			preplen
			link "bof_args"

		export

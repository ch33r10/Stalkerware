rule TrackMyPhones_jar
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detection for TrackMyPhones classes.dex"
		hash = "08c245752f689780391056c17a4fa9c5e7049352e25f11614d20e999487308a4"
		version = "0.1"
	strings:
		$ = "Cell Tracker" wide
		$ = "com.apps_era.remote_cell_tracker" wide
		$ = "res/drawable-hdpi/thieftracker.png"
		$ = "res/drawable-hdpi/call_sms_iconicon.png"
	condition:
		3 of them	
}

rule TrackMyPhones
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detection for TrackMyPhones"
		hash = "23bf97b170e152e63ab738e40746556fa66491d12870d93702b87672483a506a"
		version = "0.1"
	strings:
		$ = "thetruth-db94a.appspot.com"
		$ = "!!Actualitza Serveis de Google Play"
		$ = "com.systemservice" wide
		$ = "(Required) Hide App (only Android 10)" 
		$ = "TheTruthSpy"
		$ = "How to Hide TheTruthSpy"
	condition:
		all of them	
}

rule TalkLog
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detection for TalkLog"
		hash = "09d82667d9d72e8980e78c17898430d05a1419f2e432ee46fae1e40056df1801"
		version = "0.1"
	strings:
		$ = "https://talklog.tools/en/agreement"
		$ = "after_incoming_sms"
		$ = "after_incoming_call"
		$ = "after_outcoming_sms"
		$ = "media_wifi_info_tv"
		$ = "save photo/video"
		$ = "set duration"
		$ = "HistoryTool"
	condition:
		5 of them	
}

rule TheTruthMonitor
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detecton for TheTruthMonitor"
		hash = "1ab77b7b6e9f2461c3d12a304ce791ddc42122e070d6d2a106d47b1766705e21"
		version = "0.1"
	strings:
		$ = "assets/traceyou.db"
		$ = "res/drawable/call_incoming_icon.png"
		$ = "TheTruthSpy Monitor"
		$ = "SMS Conversation"
		$ = "res/drawable-xhdpi/spy_call_function.png"
		$ = "com.ispyoo.traceyou" wide
	condition:
		3 of them	
}

rule Xnore
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detecton for Xnore"
		hash = "35fa07d5a39c670c2143718b6cedf713f32f61d93bc264939439748f6a835cc0"
		version = "0.1"
	strings:
		$ = ",,System Servic Has Been Updated Syccessfully!"
		$ = "com.xno.systemservice" wide
	condition:
		any of them	
}

rule CocoSpy
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detecton for CocoSpy"
		hash = "416d5a5525b9d36b185fdc9538887d8c80dcd70b581d1349343e0f322ef99a22"
		version = "0.1"
	strings:
		$ = "Your code"
		$ = "Sms alert"
		$ = "com.cocospy" wide
		$ = "Send files (screenshots/photos/record) to the server only via Wi-Fi" 
		$ = "Automatically download and install new versions of DW. Requires root"
	condition:
		3 of them	
}

rule MSpyAndroidApp
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detecton for MSpyAndroidApp"
		hash = "49a4380a485809122953354e2d3ddb056e15c3386396fc07dab482c521fc1af1"
		version = "0.1"
	strings:
		$ = "android.sys.process" wide
		$ = "-%1$s ngeke ize iqalise ngaphandle kokuthi ubuyekeze i-Google Play"
		$ = "##Mostra l'icona mSpy sul dispositivo"
		$ = "+Allow Ad to store image in Picture gallery?"
		$ = "gather_btn"
	condition:
		all of them	
}
rule Reptilicus
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detecton for Android/Reptilicus"
		hash = "5205cfee818b0db012521c34c321a11d06b16bd1678df70046dfc644681e5fdb"
		version = "0.1"
	strings:
		$ = "res/drawable-mdpi/phonebook.png"
		$ = "res/layout/activity_fake.xml"
		$ = "res/layout/activity_call_record.xml"
		$ = "activity_add_device"
		$ = "activity_alarm"
		$ = "activity_call_record"
		$ = "activity_enter"
		$ = "activity_fake"
		$ = "activity_forgot_pwd"
		$ = "device_admin"
		$ = "callRecordView"
		$ = "call_record_mode"
		$ = "call_record_type"
		$ = "call_record_from_line"
		$ = "callRecordListScrollView"
		$ = "callRecordListTableLayout"		
	condition:
		10 of them	
}

rule APISpyHuman
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detecton for APISpyHuman"
		hash = "603541c26654e3da493a72c372e75049b8d5d7c0ca06ed021482298c1bd9b078"
		version = "0.1"
	strings:
		$ = "res/xml/accessallthings.xml"
		$ = "res/drawable/spyhumanlogo.png"
		$ = "res/drawable/sreen_captures.png"
		$ = "res/layout/activity_welcome_spyhuman.xml"
		$ = "Please Activate This For Preventing Uninstall"
		$ = "href=http://spyhuman.com/privacy-policy/"
		$ = "Call Details, Text-Messages, App Chats, Location and Much More..."
		$ = "By installing this application, you agree and liable to use the SpyHuman application in lawful manner. "
	condition:
		all of them	
}

rule Android_SpyC23_A
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detecton for Android/SpyC23.A"
		hash = "b2396341f77b9549f62a0ce8cc7dacf5aa250242ed30ed5051356d819b60abff"
		version = "0.1"
		ref = "https://www.welivesecurity.com/2020/09/30/aptc23-group-evolves-its-android-spyware/"
	strings:
		$ = "video_call"
		$ = "com/google/i18n/phonenumbers/data/PhoneNumberMetadataProto_ISmS"
		$ = "lib/x86/libCallRecFix.so"
		$ = "income_current_call"
	condition:
		all of them	
}

rule Spy2Mobile
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detecton for Spy2Mobile"
		hash2 = "c032a7a964ab00ac99d802380e47944993dfe83207eb37819c6a1f0d8f303e63"
		hash2 = "f904263c7475968bd87776aca3fff01586ecdceb7898f1297c17defef9efd202"
		version = "0.1"
	strings:
		$1 = "useragreement"
		$2 = "!!res/xml/watch_widget_provider.xml"
		$3 = "<a href=\"%1$s\">%1$s</a>"
		$4 = "smartback-12d60.appspot.com"
		$5 = "Your account had been created and the phone was linked to it. Your password is sent to your Email."
		$6 = "The phone was connected to another user account. Contact Tech Support %1$s"
		$info = "Access spying info in your account on http://spy2mobile.com "
	condition:
		2 of them or $info
}

rule AndroidMonitor
{
	meta:
		author = "Silas Cutler (silas@blacklab.io)"
		description = "Detecton for AndroidMonitor"
		hash = "e32cd90b7d31dd786df87e09546eee8237dbb7f83ad300407cd4e839ac2c30c1"
		version = "0.1"
	strings:
		$ = "AO; aoTuV b4b [20051117] (based on Xiph.Org's libVorbis)"
		$ = "com.android.core.monitor" wide
		$ = "Monitor enabled"
		$ = "help_status_monitor_enabled"
	condition:
		all of them
}


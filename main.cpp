#include <string>
#include <memory>
#include <windows.h>
#include <tchar.h>
#include <msi.h>
#include "resource.h"

#ifdef _UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif



//
// Win32 Utility
//

tstring getSystemDirectory()
{
	TCHAR systemDir[MAX_PATH + 1];
	DWORD systemDirLen = ::GetSystemDirectory(systemDir, MAX_PATH);
	if (systemDirLen == 0 || systemDirLen > MAX_PATH){
		return tstring();
	}
	return systemDir;
}

DWORD getFileVersionNumberMS(const tstring &pathFile, DWORD dwErrorVersion)
{
	DWORD handle = 0;
	const DWORD versionInfoSize = ::GetFileVersionInfoSize(pathFile.c_str(), &handle);
	if (versionInfoSize > 0){
		std::unique_ptr<char[]> versionInfoData(new char[versionInfoSize]);
		if (::GetFileVersionInfo(pathFile.c_str(), handle, versionInfoSize, versionInfoData.get())){
			VS_FIXEDFILEINFO  *fixedFileInfoPtr = nullptr;
			UINT fixedFileInfoSize = 0;
			if (::VerQueryValue(versionInfoData.get(), _T("\\"), (LPVOID *)&fixedFileInfoPtr, &fixedFileInfoSize)){
				if (fixedFileInfoSize >= sizeof(VS_FIXEDFILEINFO)){
					return fixedFileInfoPtr->dwFileVersionMS;
				}
			}
		}
	}
	return dwErrorVersion;
}

tstring getCurrentModulePath()
{
	const int bufferSize = MAX_PATH;
	TCHAR buffer[bufferSize + 1];
	const DWORD pathLen = ::GetModuleFileName(NULL, buffer, bufferSize);
	if (pathLen >= bufferSize){
		return tstring();
	}
	return buffer;
}

tstring getFullPathName(const tstring &path)
{
	const int bufferSize = MAX_PATH;
	TCHAR buffer[bufferSize + 1];
	LPTSTR filePartPtr = nullptr;
	const DWORD pathLen = ::GetFullPathName(path.c_str(), bufferSize, buffer, &filePartPtr);
	if (pathLen >= bufferSize){
		return tstring();
	}
	return buffer;
}

tstring getFullPathDirectoryPart(const tstring &path)
{
	const int bufferSize = MAX_PATH;
	TCHAR buffer[bufferSize + 1];
	LPTSTR filePartPtr = nullptr;
	const DWORD pathLen = ::GetFullPathName(path.c_str(), bufferSize, buffer, &filePartPtr);
	if (pathLen >= bufferSize){
		return tstring();
	}
	*filePartPtr = '\0';
	return buffer;
}

bool isFileExists(const tstring &path)
{
	return GetFileAttributes(path.c_str()) != -1;
}

tstring loadStringResource(UINT resourceId)
{
	const int bufferSize = MAX_PATH;
	TCHAR buffer[bufferSize] = {0};
	::LoadString(GetModuleHandle(NULL), resourceId, buffer, bufferSize);
	return buffer;
}

void reportError(const tstring &str)
{
	MessageBox(NULL, str.c_str(), _T("エラー"), MB_OK);
}


//
// MSI Utility
//

int getMsiVersion()
{
	const tstring pathSystemDir = getSystemDirectory();
	if (pathSystemDir.empty()){
		return 0;
	}
	const tstring pathMsiDll = pathSystemDir + _T("\\MSI.DLL");

	{
		const HINSTANCE hinstMsiDll = ::LoadLibrary(pathMsiDll.c_str());
		if (hinstMsiDll == NULL){
			return 0;
		}
		::FreeLibrary(hinstMsiDll);
	}

	return getFileVersionNumberMS(pathMsiDll, 0);
}

class MsiDll
{
	bool error_;
	HMODULE hMsi_;

#ifdef _UNICODE
# define MSIAPI_SUFFIX "W"
#else
# define MSIAPI_SUFFIX "A"
#endif

#define DEFMEMBER(resulttype, name, params, args, suffix)\
private:\
	typedef resulttype (WINAPI* PFn##name)params;\
	PFn##name pfn##name = (PFn##name)getProcAddress(#name suffix);\
public:\
	resulttype name params{ return (*pfn##name)args;}

	DEFMEMBER(INSTALLUILEVEL, MsiSetInternalUI, (INSTALLUILEVEL dwUILevel, HWND *phWnd), (dwUILevel,phWnd),);
	DEFMEMBER(UINT, MsiInstallProduct, (LPCTSTR szPackagePath, LPCTSTR szCommandLine), (szPackagePath, szCommandLine), MSIAPI_SUFFIX);
	DEFMEMBER(UINT, MsiApplyPatch, (LPCTSTR szPatchPackage, LPCTSTR szInstallPackage, INSTALLTYPE eInstallType, LPCTSTR szCommandLine), (szPatchPackage, szInstallPackage, eInstallType, szCommandLine), MSIAPI_SUFFIX);
	DEFMEMBER(UINT, MsiReinstallProduct, (LPCTSTR szProduct, DWORD dwReinstallMode), (szProduct, dwReinstallMode), MSIAPI_SUFFIX);
	DEFMEMBER(INSTALLSTATE, MsiQueryProductState, (LPCTSTR szProduct), (szProduct), MSIAPI_SUFFIX);
	DEFMEMBER(UINT, MsiOpenDatabase, (LPCTSTR szDatabasePath, LPCTSTR szPersist, MSIHANDLE *phDatabase), (szDatabasePath, szPersist, phDatabase), MSIAPI_SUFFIX);
	DEFMEMBER(UINT, MsiDatabaseOpenView, (MSIHANDLE hDatabase, LPCTSTR szQuery, MSIHANDLE *phView), (hDatabase, szQuery, phView), MSIAPI_SUFFIX);
	DEFMEMBER(UINT, MsiViewExecute, (MSIHANDLE hView, MSIHANDLE hRecord), (hView, hRecord),);
	DEFMEMBER(UINT, MsiViewFetch, (MSIHANDLE hView, MSIHANDLE *phRecord), (hView, phRecord),);
	DEFMEMBER(UINT, MsiRecordGetString, (MSIHANDLE hRecord, unsigned int uiField, LPTSTR szValue, DWORD *pcchValueBuf), (hRecord, uiField, szValue, pcchValueBuf), MSIAPI_SUFFIX);
	DEFMEMBER(UINT, MsiCloseHandle, (MSIHANDLE h), (h),);
#undef DEFMEMBER
#undef MSIAPI_SUFFIX

private:
	FARPROC getProcAddress(LPCSTR name)
	{
		if (hMsi_){
			if (FARPROC pf = ::GetProcAddress(hMsi_, name)){
				return pf;
			}
		}
		error_ = true;
		return NULL;
	}
public:
	MsiDll()
		: error_(false)
		, hMsi_(LoadLibrary(_T("msi.dll")))
	{
	}
	~MsiDll()
	{
		if (hMsi_){
			FreeLibrary(hMsi_);
		}
	}
	bool hasError()
	{
		return !hMsi_ || error_;
	}
};


//
// Launch MSI
//

tstring getMsiFile()
{
	const tstring currentModulePath = getCurrentModulePath();
	if (currentModulePath.empty()){
		return tstring();
	}
	const tstring msiFileName = loadStringResource(IDS_MSI_FILENAME);
	if (msiFileName.empty()){
		return tstring();
	}
	return getFullPathDirectoryPart(currentModulePath) + msiFileName;
}

bool executeMsiFile(const tstring &file)
{
	MsiDll msi;
	if (msi.hasError()){
		reportError(_T("msi.dll内の関数を読み込めませんでした。"));
		return false;
	}

	msi.MsiSetInternalUI(INSTALLUILEVEL_FULL, NULL);
	msi.MsiInstallProduct(file.c_str(), _T(""));

	return true;
}



int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR lpCmdLIne, int nCmdShow)
{
	// Windows Installerの存在を確認する。
	if (getMsiVersion() < 0x200){
		reportError(_T("Windows Installerが見つかりませんでした。Windows Installerをインストールしてから再度セットアップを実行してください。"));
		return 0;
	}
	// MSIファイルを特定する。
	const tstring msiPath = getMsiFile();
	if (msiPath.empty()){
		reportError(_T(".msiファイル名を特定できませんでした。"));
		return 0;
	}
	if (!isFileExists(msiPath)){
		reportError(_T("インストールに必要なファイルが見つかりませんでした。\n") + msiPath);
		return 0;
	}
	// MSIファイルを実行する。
	executeMsiFile(msiPath);
	return 0;
}

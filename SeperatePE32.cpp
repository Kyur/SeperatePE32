#include <windows.H>
#include <stdio.h>
#include <tchar.h>

int main(int argc, TCHAR** argv)
{
	WIN32_FIND_DATA lpFileData;
	TCHAR targetPath[MAX_PATH] = { NULL, };
	TCHAR targetPathFiles[MAX_PATH] = { NULL, };
	TCHAR targetFileName[MAX_PATH] = { NULL, };
	TCHAR copyFile[MAX_PATH] = { NULL, };
	TCHAR dumpDir[MAX_PATH] = { NULL, };
	HANDLE hFindFirstFile = INVALID_HANDLE_VALUE;
	HANDLE hTargetFile = INVALID_HANDLE_VALUE;
	DWORD lpNumberOfBytesRead = 0;
	DWORD elfanew = 0;
	DWORD bitFlag = 0;

	PBYTE lpMem = NULL;

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;

	if(argc != 2)
	{
		printf(" Usage: SeperatePE32.exe [Tartget Folder]\n");
		return -1;
	}

	// Set base target folder path
	strncpy(targetPath, argv[1], strlen(argv[1]));
	
	strncpy(targetPathFiles, targetPath, strlen(targetPath));
	strncpy(dumpDir, targetPath, strlen(targetPath));
	strcat(targetPathFiles, "\\*");	
	strcat(dumpDir, "\\DUMP_FILES");

	// Start search files
	hFindFirstFile = FindFirstFile(targetPathFiles, &lpFileData);
	if(hFindFirstFile == INVALID_HANDLE_VALUE)
	{
		printf(" Fail to FindFirstFile. - %08X\n", GetLastError());
		return -1;
	}

	// Create dump directory
	if(!CreateDirectory(dumpDir, NULL))
	{
		printf(" Fail to CreateDirectory. - %08X\n", GetLastError());
		return -1;
	}

	do
	{
		bitFlag = 0;

		// exclusive directory
		if(lpFileData.dwFileAttributes != FILE_ATTRIBUTE_DIRECTORY)
		{
			sprintf(targetFileName, "%s\\%s", targetPath, lpFileData.cFileName);

			hTargetFile = CreateFile(targetFileName, GENERIC_READ|GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if(hTargetFile == INVALID_HANDLE_VALUE)
			{
				printf(" Fail to CreateFile. - %08X\n", GetLastError());
				return -1;
			}

			lpMem = (PBYTE)VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

			// Read file data (0x1000)
			ReadFile(hTargetFile, lpMem, 0x1000, &lpNumberOfBytesRead, NULL);
			if(lpNumberOfBytesRead == 0)
			{
				printf(" Fail to ReadFile - %08X\n", GetLastError());
				return -1;
			}
			CloseHandle(hTargetFile);
			
			// Check PE file
			if(memcmp(lpMem, "MZ", 0x2))
			{
				printf(" Not pe file : %s\n", targetFileName);
				
				VirtualFree(lpMem, 0x1000, MEM_RELEASE);
				continue;
			}

			pDosHeader = (PIMAGE_DOS_HEADER)lpMem;
			elfanew = pDosHeader->e_lfanew;
			pNtHeader = (PIMAGE_NT_HEADERS)(lpMem + elfanew);


			// # Check PE32 magic
			if( pNtHeader->OptionalHeader.Magic == 0x020B)
			{
				// PE32+
				bitFlag = 64;
				sprintf(copyFile, "%s\\64_%s", dumpDir, lpFileData.cFileName);
				if(!CopyFile(targetFileName, copyFile, FALSE))
				{
					printf(" Fail to CopyFile. - %08X\n", GetLastError());
					return -1;
				}
			}
			else
			{
				// PE32
				bitFlag = 32;
				sprintf(copyFile, "%s\\32_%s", dumpDir, lpFileData.cFileName);
				if(!CopyFile(targetFileName, copyFile, FALSE))
				{
					printf(" Fail to CopyFile. - %08X\n", GetLastError());
					return -1;
				}
			}

			VirtualFree(lpMem, 0x1000, MEM_RELEASE);
			printf(" Classification file : %s - %d\n", lpFileData.cFileName, bitFlag);
		}		

	}while(FindNextFile(hFindFirstFile, &lpFileData));

	FindClose(hFindFirstFile);

	return 1;
}
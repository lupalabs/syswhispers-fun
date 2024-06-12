#include <windows.h>
#include <stdio.h>
#include "syscall_process.h"
//#include <ntdef.h>
//#include "ntdll_defs.h"
//#include "ntdll_funcs.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

int main(int argc, char* argv[]) {

    printf("Starting ...\n");

    HANDLE hProcess, hThread = NULL;

    UNICODE_STRING NtImagePath;
	RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\calc.exe");

    printf("Created Unicode String ...\n");

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	NTSTATUS status = RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
    printf("Created Process Parameters (Status: %lx) ...\n", status);

    PS_CREATE_INFO CreateInfo = {0};
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;

    PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[0].Size = NtImagePath.Length;
	AttributeList->Attributes[0].u1.ValuePtr = NtImagePath.Buffer;

    AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
	AttributeList->Attributes[1].Size = sizeof(HANDLE);
	AttributeList->Attributes[1].u1.ValuePtr = GetCurrentProcess();
    
    printf("Trying to create process ...\n");
    status = NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, ProcessParameters, &CreateInfo, AttributeList);
    printf("Created process with status %lx ...\n", status);

    BOOLEAN bStatus = RtlFreeHeap(GetProcessHeap(), 0, AttributeList);
    printf("Freed Heap with status %d ...\n", bStatus);

    status = RtlDestroyProcessParameters(ProcessParameters);
    printf("Destroyed parameters with status %lx ...\n", status);

    return 0;
}
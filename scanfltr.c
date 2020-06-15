/*++

Module Name:

    scanfltr.c

Abstract:

    This is the main module of the scanfltr miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>

#include <ntstrsafe.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
scanfltrInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
scanfltrInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
scanfltrInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
scanfltrUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
scanfltrInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
scanfltrPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
scanfltrOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
scanfltrPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
scanfltrPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
scanfltrDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, scanfltrUnload)
#pragma alloc_text(PAGE, scanfltrInstanceQueryTeardown)
#pragma alloc_text(PAGE, scanfltrInstanceSetup)
#pragma alloc_text(PAGE, scanfltrInstanceTeardownStart)
#pragma alloc_text(PAGE, scanfltrInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_CLOSE,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_READ,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },
#endif 

    { IRP_MJ_WRITE,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_QUERY_INFORMATION,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_SET_EA,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      scanfltrPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_PNP,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      scanfltrPreOperation,
      scanfltrPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    scanfltrUnload,                           //  MiniFilterUnload

    scanfltrInstanceSetup,                    //  InstanceSetup
    scanfltrInstanceQueryTeardown,            //  InstanceQueryTeardown
    scanfltrInstanceTeardownStart,            //  InstanceTeardownStart
    scanfltrInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};

NTSTATUS  logOpen();
NTSTATUS WriteToLogFile(PFLT_INSTANCE Inst, PUCHAR buff, ULONG bufflen);
void logClose();

struct DataGlobal {
	HANDLE hLog;
	PFILE_OBJECT logFO;
	BOOLEAN blogInitilized;
} DrvGlobal;
FLT_PREOP_CALLBACK_STATUS
scanSignature(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

NTSTATUS
scanfltrInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("scanfltr!scanfltrInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
scanfltrInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("scanfltr!scanfltrInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
scanfltrInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("scanfltr!scanfltrInstanceTeardownStart: Entered\n") );
}


VOID
scanfltrInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("scanfltr!scanfltrInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("scanfltr!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }
	logOpen();
    return status;
}

NTSTATUS
scanfltrUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("scanfltr!scanfltrUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );
	logClose();
    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
scanfltrPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("scanfltr!scanfltrPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //
	switch (Data->Iopb->MajorFunction) {
	case IRP_MJ_WRITE:
		scanSignature(Data, FltObjects, CompletionContext);
		break;
		
	}
    if (scanfltrDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    scanfltrOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("scanfltr!scanfltrPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
scanfltrOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("scanfltr!scanfltrOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("scanfltr!scanfltrOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
scanfltrPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("scanfltr!scanfltrPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
scanfltrPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("scanfltr!scanfltrPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
scanfltrDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

PVOID
scanMapUserBuffer(
	_Inout_ PFLT_CALLBACK_DATA Data
)
{
	if (Data->Iopb->Parameters.Write.MdlAddress == NULL) {
		return  Data->Iopb->Parameters.Write.WriteBuffer;;
	}
	else {
		PVOID Address = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress,
			NormalPagePriority | MdlMappingNoExecute);
		
		return Address;
	}
}

int  KMPSearch(unsigned char* pat, ULONG M, unsigned char* txt, ULONG N);
ULONG patternMatch(PUCHAR strBuff, ULONG strLen, PUCHAR patBuff, ULONG patLen) {
	ULONG   matchedAt = MAXULONG;
	int  indx = 0;
	if (strLen < patLen) {
		goto end;
	}
	indx = KMPSearch(patBuff, patLen, strBuff, strLen);

	if (-1 == indx)
		return matchedAt;
	matchedAt = indx;
		/*
	for (ULONG i = 0; i <= strLen- patLen; i++) {
		if (patLen == RtlCompareMemory(strBuff + i, patBuff, patLen)) {
			matchedAt = i;
			break;
		}
	} */
end:
	return matchedAt;
}
FLT_PREOP_CALLBACK_STATUS
scanSignature(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{

	UNICODE_STRING	uSigNature = RTL_CONSTANT_STRING(L"Microsoft Screen Magnifier");
	PVOID			wbuffer = NULL;
	ULONG			wLen = Data->Iopb->Parameters.Write.Length;
	ULONG			RetiaveOffsetFound = FALSE;
	NTSTATUS		status = STATUS_SUCCESS;
	char logBuff[1024]={0,};

	ULONG MaxlogBuffLen = sizeof(logBuff);
	size_t logBuffLen = 0;
	UNREFERENCED_PARAMETER(CompletionContext);

	if (wLen == 0) {
		goto end;
	}
	wbuffer = scanMapUserBuffer(Data);

	if (wbuffer == NULL) {
		goto end;
	}
	
	RetiaveOffsetFound = patternMatch(wbuffer, wLen, (PUCHAR)uSigNature.Buffer, uSigNature.Length);
	if (RetiaveOffsetFound == MAXULONG) {
		DbgPrint("signature not found in write %wZ", FltObjects->FileObject->FileName);
		goto end;
	}

	DbgPrint("scanSignature: Signature FOUND @%lld in %wZ", Data->Iopb->Parameters.Write.ByteOffset.QuadPart  + RetiaveOffsetFound,FltObjects->FileObject->FileName);
	if(!DrvGlobal.blogInitilized){ 
		goto end;
	}
	status = RtlStringCbPrintfA(logBuff, MaxlogBuffLen, "Signature FOUND @%lld in %wZ\r\n", Data->Iopb->Parameters.Write.ByteOffset.QuadPart  + RetiaveOffsetFound,FltObjects->FileObject->FileName);
	
	if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW){

		DbgPrint("RtlStringCbPrintfA failled ");
		goto end;
	}

	status = RtlStringCbLengthA(logBuff, MaxlogBuffLen, (size_t *)&logBuffLen);
	if (!NT_SUCCESS(status))
	{
		goto end;
	}
	status = WriteToLogFile(FltObjects->Instance, (PUCHAR)logBuff, (ULONG)logBuffLen);
	if (!NT_SUCCESS(status))
	{
		goto end;
	}
end:

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS  logOpen()
{

	wchar_t *filename = L"\\DosDevices\\C:\\Malware.Log";
	NTSTATUS sts = STATUS_SUCCESS;
	IO_STATUS_BLOCK ioStatus = { 0, };
	OBJECT_ATTRIBUTES  oa;
	UNICODE_STRING logFname = { 0, };
	HANDLE hLOG = NULL;
	PFILE_OBJECT logFO;

	RtlInitUnicodeString(&logFname, filename);

	InitializeObjectAttributes(&oa,
		&logFname,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	sts = ZwCreateFile(&hLOG,
		GENERIC_ALL | DELETE,
		&oa,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 
		NULL,
		0);

	if (!NT_SUCCESS(sts))
	{
		DbgPrint("Failed to open Log file status = %0x", sts);
		goto end;
	}

	sts = ObReferenceObjectByHandle(hLOG, 0, NULL, KernelMode, (PVOID *)&logFO, NULL);
	if (!NT_SUCCESS(sts))
	{
		DbgPrint("Failed to grab FileOBject  to Log file status = %0x", sts);
		goto end;
	}


	DrvGlobal.hLog = hLOG;
	DrvGlobal.logFO = logFO;
	DrvGlobal.blogInitilized = TRUE;
end:
	return sts;
}


NTSTATUS WriteToLogFile(PFLT_INSTANCE Inst,PUCHAR buff, ULONG bufflen)
{

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ULONG Flags = 0L;
	ULONG BytesWritten = 0;

 	if (NULL == DrvGlobal.logFO
		|| !DrvGlobal.blogInitilized)
		goto end;
	status = FltWriteFile(Inst,
		DrvGlobal.logFO,
		NULL,
		bufflen,
		buff,
		Flags,
		&BytesWritten,
		NULL,
		NULL);

end:
	return status;
}


void logClose()
{
	if (DrvGlobal.hLog != NULL)
		ZwClose(DrvGlobal.hLog);
	if (DrvGlobal.logFO != NULL)
		ObDereferenceObject(DrvGlobal.logFO);
	DrvGlobal.blogInitilized = FALSE;
}
void computeLPSArray(unsigned char* pat, ULONG M, ULONG * lps);

int  KMPSearch(unsigned char* pat, ULONG M, unsigned char* txt, ULONG N)
{
	ULONG * lps = (ULONG*) ExAllocatePool(PagedPool, sizeof(ULONG)*M);
	computeLPSArray(pat, M, lps);

	ULONG i = 0;
	ULONG j = 0;
	while (i < N) {
		if (pat[j] == txt[i]) {
			j++;
			i++;
		}

		if (j == M) {
			return i - j;
		}
		else if (i < N && pat[j] != txt[i]) {
			if (j != 0)
				j = lps[j - 1];
			else
				i = i + 1;
		}
	}
	ExFreePool(lps);
	return -1;
}
void computeLPSArray(unsigned char* pat, ULONG M, ULONG * lps)
{
	ULONG len = 0;
	lps[0] = 0;
	ULONG i = 1;
	while (i < M) {
		if (pat[i] == pat[len]) {
			len++;
			lps[i] = len;
			i++;
		}
		else 
		{
			if (len != 0) {
				len = lps[len - 1];
			}
			else {
				lps[i] = 0;
				i++;
			}
		}
	}
}
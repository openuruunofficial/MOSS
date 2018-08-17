{
  ManifestCreator - Makes binary manifest files required for MOSS servers
  Copyright (C) 2008-2011  cjkelly1

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
}

unit Main;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, StrUtils, zlibexGZ, ComCtrls, DateUtils, Gauges, ShellAPI,
  ShlObj, TimeZoneConversion, DCPmd5, ExtCtrls;

const
  Thread_Message  = WM_USER + 1;
  // wparm items
  Thread_ItemCompleted = 1;
  Thread_Completed = 2;
  Thread_Stopped = 3;

type
  DataServer = record
    SizeOfEntry: DWORD;
    ClientPathAndFile: WideString;
    ServerPath, UncompressedFileMD5Sum, CompressedFileMD5Sum: WideString;
    UncompressedSize: dword; // convert to six byte funky size later
    CompressedSize: dword; // convert to six byte funky size later
    FileFlags: DWORD;
    Result: string;
  end;

  AuthServer = record
    ClientAndServerPath: String;
    ObjectSize: dword; // convert to six byte funky size later
    Result: string;
  end;

  TThreadInfo = record
    Active: boolean;
    Closed: boolean;
    ThreadHandle : integer;
    ThreadId     : Cardinal;
  end;

  TForm1 = class(TForm)
    Memo1: TMemo;
    OpenDialog1: TOpenDialog;
    btnStop: TButton;
    txtSourcePath: TEdit;
    lblSourcePath: TLabel;
    btnChangePath: TButton;
    pnlControls: TPanel;
    btnMakeManifest: TButton;
    btnClear: TButton;
    chkOverwrite: TCheckBox;
    cboManifestType: TComboBox;
    lblManifestType: TLabel;
    gauCurrentProgress: TGauge;
    Label1: TLabel;
    gauTotalManifests: TGauge;
    Label2: TLabel;
    procedure btnClearClick(Sender: TObject);
    procedure cboManifestTypeChange(Sender: TObject);
    procedure btnStopClick(Sender: TObject);
    procedure btnChangePathClick(Sender: TObject);
    procedure btnMakeManifestClick(Sender: TObject);
    procedure OnCreate(Sender: TObject);
    procedure OnDestroy (Sender: TObject);
    procedure FormCloseQuery (Sender: TObject; var CanClose: Boolean);
    procedure chkOverwriteClick(Sender: TObject);

  private
    ThreadInfo : array[0..7] of TThreadInfo;  // 8 threads
    procedure ThreadMessage( var Message : TMessage ); message Thread_Message;
    function ThreadIDToIndex(ThreadID: Cardinal): integer;
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation
{$R *.dfm}

var
  Dir: string;
  CriticalSection : TRTLCriticalSection;
  DataServerManifest: array of DataServer;
  AuthServerManifest: array of AuthServer;
  StopNow, OverwriteExisting, CloseApp, ErrorFlag: boolean;
  ManifestList: TStringList;
  ManifestIndex, NextManifestItem, TotalThreads: integer;
  FilePath, SourcePath: string;

{
  *** Dataserver manifest file formats ***

Text file format (processed by ManifestCreator into an MBM file:
  One line per file to be included in manifest.

  [File path on client, file path on server, type]

Example:
  dat\StartUp_District_GUIDialog04c.prp,Data\dat\StartUp_District_GUIDialog04c.prp.gz,0

MBM (Moss Binary Manifest) file format:

DWORD NumberOfObjects
  [ DWORD SizeOfEntry
    WideString ClientPathAndFile
    WideString ServerPath
    UncompressedFileMD5Sum
    CompressedFileMD5Sum
    UncompressedSize (six byte funky size)
    CompressedSize (six byte funky size)
    Empty WideString (two bytes)
    DWORD FileFlags
  ] x NumberOfObjects


   *** Auth server manifest file formats ***

Text file format:
  One line per file to be included in manifest.

  [ path and file name on client *and* server]

Example:
  SDL\BaronCityOffice.sdl

MBAM (Moss Binary Auth Manifest) file format:
  [ WideString  ClientAndServerPath
    ObjectSize (Six byte funky size)
  ]

}

function IntToBin ( value: LongInt; digits: integer ): string;
begin
  result := StringOfChar ( '0', digits ) ;
  while value > 0 do
  begin
    if ( value and 1 ) = 1 then result [ digits ] := '1';
    dec ( digits ) ;
    value := value shr 1;
  end;
end;

// http://www.delphipages.com/forum/showpost.php?s=d87ace12b09c52fd59909766bb528657&p=81591&postcount=5
Procedure Split(S, Delimiter: string; Strings: TStrings);
var
  P, OldP: integer;
  Token: string;
begin
  if (Strings = nil) or (Length(S) = 0) or (Length(Delimiter) = 0) then exit;
  P := Pos(Delimiter, S);
  OldP := 1;
  while P > 0 do
  begin
    Token := Copy(S, OldP, P-OldP);
    Strings.Add(Token);
    OldP := P + 1;
    P := PosEx(Delimiter, S, OldP);
  end;
  if P = 0 then Strings.Add(Copy(S, OldP, Length(S)));
end;

function MakeSizeFunky(InDWORD: dword): dword;
asm
  ror eax, 16
end;

procedure WriteWideChar(InputString: String; MemoryStream: TFileStream);
var
  WideLen: Integer;
  ConvertedToWide: PWideChar;
Begin
  WideLen := Length(InputString) * SizeOf(WideChar) + 2;
  GetMem(ConvertedToWide, WideLen);
  StringToWideChar(InputString, ConvertedToWide, WideLen);
  MemoryStream.WriteBuffer(ConvertedToWide^, WideLen);
  FreeMem(ConvertedToWide);
end ;

Procedure WriteFunkySize(FileSize: DWORD; MemoryStream: TFileStream);
const
  NullWideChar: WORD = $0000;
var
 FunkySize: DWORD;
begin
  FunkySize := MakeSizeFunky(FileSize);
  MemoryStream.WriteBuffer(FunkySize, 4);
  MemoryStream.WriteBuffer(NullWideChar, 2);
end;


function IsNumeric(const Text: String): Boolean;
begin
  if Text[1] in ['0'..'9'] then
    Result := TRUE
  else
    Result := FALSE;
end;

function BrowseDialogCallBack(Wnd: HWND; uMsg: UINT; lParam, lpData: LPARAM): integer stdcall;
var
  wa, rect : TRect;
  dialogPT : TPoint;
begin
  //center in work area
  if uMsg = BFFM_INITIALIZED then
  begin
    wa := Screen.WorkAreaRect;
    GetWindowRect(Wnd, Rect);
    dialogPT.X := ((wa.Right-wa.Left) div 2) - ((rect.Right-rect.Left) div 2);
    dialogPT.Y := ((wa.Bottom-wa.Top) div 2) -  ((rect.Bottom-rect.Top) div 2);
    MoveWindow(Wnd, dialogPT.X, dialogPT.Y, Rect.Right - Rect.Left, Rect.Bottom - Rect.Top, True);
  end;
  Result := 0;
end;

function BrowseDialog (const Title: string; Flag: integer): string;
var
  lpItemID : PItemIDList;
  BrowseInfo : TBrowseInfo;
  DisplayName : array[0..MAX_PATH] of char;
  TempPath : array[0..MAX_PATH] of char;
begin
  Result:='';
  FillChar(BrowseInfo, sizeof(TBrowseInfo), #0);
  with BrowseInfo do
  Begin
    hwndOwner := Application.Handle;
    pszDisplayName := @DisplayName;
    lpszTitle := PChar(Title);
    ulFlags := Flag;
    lpfn := BrowseDialogCallBack;
  end;
  lpItemID := SHBrowseForFolder(BrowseInfo);
  if lpItemId <> nil then
  Begin
    SHGetPathFromIDList(lpItemID, TempPath);
    Result := TempPath;
    GlobalFreePtr(lpItemID);
  end;
end;

Function GetUnixTime(FileName: string): DWORD;
Var
  pHandle: THandle;
  sFileTime: TFileTime;
  Timestamp: Int64;
Begin
  pHandle := CreateFile(PChar(FileName),GENERIC_READ,0,nil,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,0);
  If pHandle = 0 then
  begin
    Result:= 0;
    exit;
  end;
  GetFileTime(pHandle,nil,nil,@sFileTime);
  FileClose(pHandle);
  Timestamp := Int64(sFileTime.dwHighDateTime) shl Int64(32) + Int64(sFileTime.dwLowDateTime);
  Timestamp := Timestamp - 116444736000000000;
  Timestamp := trunc(Timestamp / 10000000);
  If Timestamp < 0 then
    Result := 0
  else
    Result := timestamp;
End;

procedure ParseManifest(ManifestToParse: string; ManifestType: integer);
var
  FileList, WorkList: TStringList;
  FileIndex, ParseManifestIndex: Integer;
begin
  // Init variables
  FileList := TStringList.Create;
  WorkList := TStringList.Create;
  ParseManifestIndex := 0;

  Try
    FileList.Clear;
    try
      FileList.LoadFromFile(ManifestToParse);
    except
      on E:EFOpenError do
      begin
        Form1.Memo1.Lines.Add(' *** ERROR *** - ' + E.Message);
        ErrorFlag:=true;
        exit;
      end;
    end;
    Form1.Memo1.Lines.Add('Processing manifest text file "' + ManifestToParse + '".' + #13#10 +
                           'Lines in file: ' + IntToStr(FileList.Count));

    if ManifestType = 0 then // Data server manifest
    begin
      SetLength(DataServerManifest, 0);
      SetLength(DataServerManifest, FileList.Count);
      for FileIndex := 0 to FileList.Count - 1 do
      begin
        WorkList.Clear;
        Split(FileList[FileIndex],',',WorkList);
        If Worklist.Count <> 3 then
        Begin
            Form1.Memo1.Lines.Add('  *** ERROR*** :  Incorrect number of parameters on line ' + IntToStr(FileIndex + 1)
                                  + '.  Skipping it.');
            ErrorFlag:=true;
        end
        else
        if (WorkList.Count = 0) or  (LeftStr(WorkList[0],1) = '#') or (LeftStr(WorkList[0],1) = '') then
          //do nothing - comment line or blank line
        else
        begin
          with DataServerManifest[ParseManifestIndex] do
          begin
            ClientPathAndFile := WorkList[0];
            ServerPath := WorkList[1];
            FileFlags := StrToInt(WorkList[2]);
          end;
          ParseManifestIndex := ParseManifestIndex + 1;
        end;
      end;
      SetLength(DataServerManifest, ParseManifestIndex);
    end
    else  // AuthServer manifest
    begin
      SetLength(AuthServerManifest, 0);
      SetLength(AuthServerManifest, FileList.Count);
      for FileIndex := 0 to FileList.Count - 1 do
      begin
        if (LeftStr(FileList[FileIndex],1) = '#') or (LeftStr(FileList[FileIndex],1) = '') then
          // do nothing - comment line or blank line
        else
        begin
          AuthServerManifest[ParseManifestIndex].ClientAndServerPath := FileList[FileIndex];
          ParseManifestIndex := ParseManifestIndex +1;
        end;
      end;
      SetLength(AuthServerManifest, ParseManifestIndex);
    end;
  Finally
    Form1.gauCurrentProgress.MaxValue := ParseManifestIndex;
    FileList.Free;
    WorkList.Free;
  end;
end;

procedure ManifestWorker(data: Pointer);
var
  PathExists, Completed, CompressedFileSame : boolean;
  ManifestType : integer;
  Index, ThreadIndex, i : integer;
  UncompressedFileSize, FileUnixTime, GzipTimestamp, WorkDWORD : DWORD;
  OutCompressStream, FileStream: TMemoryStream;
  searchResult : TSearchRec;
  TheDateTime: TDateTime;
  HashArray: array[0..15] of byte;
  MD5Hash: TDCP_MD5;
  UncompressedHash, CompressedHash, FName: string;
  ExistingCompressedFile: file;

begin
  Completed := false;
  index:= 0;
  ManifestType := Form1.cboManifestType.ItemIndex;
  if ManifestType = 0 then    // data server manifest
  begin
    while not Completed do
    begin
      EnterCriticalSection(CriticalSection);  // CS1E
      if NextManifestItem < length(DataServerManifest) then
      begin
        try
          index := NextManifestItem;  // save our index
          NextManifestItem := NextManifestItem + 1;  // increment the index pointer
          DataServerManifest[index].Result := 'Processing';
          LeaveCriticalSection(CriticalSection);  // CS1L
          // do manifest processing
          CompressedFileSame := FALSE;
          FileStream := TMemoryStream.Create;

          try
           FileStream.LoadFromFile(SourcePath+DataServerManifest[index].ClientPathAndFile);
          except
            on E:EFOpenError do
            begin
              EnterCriticalSection(CriticalSection);
              DataServerManifest[index].Result := E.Message;
              ErrorFlag:=true;
              LeaveCriticalSection(CriticalSection);
              continue;
            end;
          end;

          FileUnixTime := GetUnixTime(SourcePath+DataServerManifest[index].ClientPathAndFile);
          TheDateTime := LocaleDateTimeToGMTDateTime(FileDateToDateTime(FileAge(SourcePath+DataServerManifest[index].ClientPathAndFile)));
          FName := ExtractFileName(DataServerManifest[index].ClientPathAndFile);

{$REGION 'UncompressedHashAndSize'}
          UncompressedHash := '';
          FileStream.Position := 0;
          UncompressedFileSize := FileStream.size;
          MD5Hash := TDCP_MD5.Create(nil);
          MD5Hash.Init;
          MD5Hash.UpdateStream(FileStream,FileStream.Size);
          MD5Hash.Final(HashArray);
          for i:= 0 to 15 do
            UncompressedHash:= UncompressedHash + IntToHex(HashArray[i],2);
          UncompressedHash := LowerCase(UncompressedHash);
          MD5Hash.Free;
          FileStream.Position := 0;
          EnterCriticalSection(CriticalSection);
          DataServerManifest[index].UncompressedFileMD5Sum := UncompressedHash;
          DataServerManifest[index].UncompressedSize := UncompressedFileSize;
          LeaveCriticalSection(CriticalSection);
{$ENDREGION}

          EnterCriticalSection(CriticalSection);
          PathExists := DirectoryExists(ExtractFilePath(FilePath + DataServerManifest[index].ServerPath));
          if (not PathExists) then
            if not (ForceDirectories(ExtractFilePath(FilePath + DataServerManifest[index].ServerPath))) then
            begin
              DataServerManifest[index].Result := 'Could not create directory ' + ExtractFilePath(DataServerManifest[index].ServerPath)
                + '.  Error number:' + IntToStr(GetLastError);;
            end;
          LeaveCriticalSection(CriticalSection);

{$REGION 'CheckForExistingFile'}
          If FileExists(FilePath + DataServerManifest[index].ServerPath) then
          Begin
            AssignFile(ExistingCompressedFile,FilePath + DataServerManifest[index].ServerPath);
            try
              Reset(ExistingCompressedFile,1);
            except
              on E:EInOutError do
              begin
                EnterCriticalSection(CriticalSection);
                DataServerManifest[index].Result := 'Could not load existing compressed file - ' + E.Message;
                ErrorFlag:=true;
                LeaveCriticalSection(CriticalSection);
                continue;
              end;
            end;
            Seek(ExistingCompressedFile,4);
            BlockRead(ExistingCompressedFile,GzipTimestamp,4);
            CloseFile(ExistingCompressedFile);
            if (FileUnixTime > 0) AND (FileUnixTime = GzipTimestamp) then
              CompressedFileSame := TRUE
            else
              if (FileUnixTime = 0) AND (TheDateTime = UnixToDateTime(GzipTimestamp)) then
                CompressedFileSame := TRUE;
            end;
{$ENDREGION}

            If (CompressedFileSame) and (OverwriteExisting = FALSE) then
              // No need to compress, but need to load it to hash it
            begin
              OutCompressStream := TMemoryStream.Create;
              OutCompressStream.LoadFromFile(FilePath+DataServerManifest[index].ServerPath);
              CompressedHash := '';
              OutCompressStream.Position := 0;
              MD5Hash := TDCP_MD5.Create(nil);
              MD5Hash.Init;
              MD5Hash.UpdateStream(OutCompressStream,OutCompressStream.Size);
              MD5Hash.Final(HashArray);
              for i:= 0 to 15 do
                CompressedHash:= CompressedHash + IntToHex(HashArray[i],2);
              CompressedHash := LowerCase(CompressedHash);
              MD5Hash.Free;
              OutCompressStream.Position := 0;
              EnterCriticalSection(CriticalSection);
              DataServerManifest[index].CompressedFileMD5Sum := CompressedHash;
              DataServerManifest[index].CompressedSize := OutCompressStream.Size;
              LeaveCriticalSection(CriticalSection);
            end
            else   //do the compression
              begin
                If UncompressedFileSize = 0 then
                Begin
                  OutCompressStream := TMemoryStream.Create;
                  WorkDWORD := $08088B1F;
                  OutCompressStream.WriteBuffer(WorkDWORD, 4);
                  WorkDWORD := $00000000;
                  OutCompressStream.WriteBuffer(WorkDWORD, 4);
                  WorkDWORD := $0000FF02;
                  OutCompressStream.WriteBuffer(WorkDWORD, 2);
                  OutCompressStream.WriteBuffer(Pointer(FName)^, Length(FName));
                  WorkDWORD := $00000300;
                  OutCompressStream.WriteBuffer(WorkDWORD, 4);
                  WorkDWord := $00000000;
                  OutCompressStream.WriteBuffer(WorkDWORD, 4);
                  OutCompressStream.WriteBuffer(WorkDWORD, 3);
                  EnterCriticalSection(CriticalSection);
                  DataServerManifest[index].Result := 'zero length input file';
                  LeaveCriticalSection(CriticalSection);
                end
                else
                begin
                  OutCompressStream := TMemoryStream.Create;
                  GZCompressStream(FileStream, OutCompressStream, FName,'',TheDateTime);
                end;

                If FileUnixTime > 0 then
                begin
                  OutCompressStream.Seek(4,soFromBeginning);
                  OutCompressStream.WriteBuffer(FileUnixTime,4);
                end;

                try
                  OutCompressStream.SaveToFile(FilePath + DataServerManifest[index].ServerPath);
                except
                  on E:EInOutError do
                  begin
                    EnterCriticalSection(CriticalSection);
                    DataServerManifest[index].Result := 'Could not save compressed file - ' + E.Message;
                    ErrorFlag:=true;
                    LeaveCriticalSection(CriticalSection);
                    continue;
                  end;
                end;
                CompressedHash := '';
                OutCompressStream.Position := 0;
                MD5Hash := TDCP_MD5.Create(nil);
                MD5Hash.Init;
                MD5Hash.UpdateStream(OutCompressStream,OutCompressStream.Size);
                MD5Hash.Final(HashArray);
                for i:= 0 to 15 do
                  CompressedHash:= CompressedHash + IntToHex(HashArray[i],2);
                CompressedHash := LowerCase(CompressedHash);
                MD5Hash.Free;
                EnterCriticalSection(CriticalSection);
                DataServerManifest[index].CompressedFileMD5Sum := CompressedHash;
                DataServerManifest[index].CompressedSize := OutCompressStream.Size;
                LeaveCriticalSection(CriticalSection);
              end;
        finally
          FreeAndNil(OutCompressStream);
          FreeAndNil(FileStream);
          EnterCriticalSection(CriticalSection);
          if DataServerManifest[index].Result = 'Processing' then
            DataServerManifest[index].Result := 'Success';
          LeaveCriticalSection(CriticalSection);
          if StopNow then
          begin
            PostMessage(Form1.Handle, Thread_Message, Thread_Stopped , Windows.GetCurrentThreadID);
            Completed := True;
          end
          else
           PostMessage(Form1.Handle, Thread_Message, Thread_ItemCompleted , Index);
        end;
      end
      else
      begin
        LeaveCriticalSection(CriticalSection);  // CS1L
        if StopNow then
        begin
          PostMessage(Form1.Handle, Thread_Message, Thread_Stopped , Windows.GetCurrentThreadID);
          Completed := True;
        end
        else
        begin
          PostMessage(Form1.Handle, Thread_Message, Thread_Completed , Windows.GetCurrentThreadID);
          Completed := True;
        end;
      end;
    end;
  end

  else  //manifest type is 1 (auth manifest)
    while not Completed do
    begin
      if NextManifestItem < length(AuthServerManifest) then
      begin
        EnterCriticalSection(CriticalSection);
        index := NextManifestItem;  // save our index
        NextManifestItem := NextManifestItem + 1;  // increment the index pointer
        AuthServerManifest[index].Result := 'Processing';
        LeaveCriticalSection(CriticalSection);
        // do manifest processing
        if FindFirst((Dir + ExtractFileName(AuthServerManifest[index].ClientAndServerPath)), faAnyFile, searchResult) = 0 then
        begin
          EnterCriticalSection(CriticalSection);
          AuthServerManifest[index].ObjectSize := searchResult.Size;
          AuthServerManifest[index].Result := 'Success';
          LeaveCriticalSection(CriticalSection);
          FindClose(searchResult);
        end
        else
        begin
          EnterCriticalSection(CriticalSection);
          AuthServerManifest[index].ObjectSize := 0;
          AuthServerManifest[index].Result := 'File not found';
          LeaveCriticalSection(CriticalSection);
          FindClose(searchResult);
        end;
        PostMessage(Form1.Handle, Thread_Message, Thread_ItemCompleted , Index);
      end
      else
      begin
        EnterCriticalSection(CriticalSection);
        ThreadIndex := Form1.ThreadIDToIndex(Windows.GetCurrentThreadID);
        if ThreadIndex <> -1 then Form1.ThreadInfo[ThreadIndex].Active := false;
        LeaveCriticalSection(CriticalSection);
        PostMessage(Form1.Handle, Thread_Message, Thread_Completed , Windows.GetCurrentThreadID);
        Completed := True;
      end;
    end;
end;

procedure StartThreads();
var
  counter: integer;
begin
  for counter := 0 to TotalThreads do
  begin
    Form1.ThreadInfo[counter].ThreadHandle := BeginThread(nil, 0, @ManifestWorker, nil, 0, Form1.ThreadInfo[counter].ThreadId);
    Form1.ThreadInfo[counter].Active := true;
    Form1.ThreadInfo[counter].Closed := false;
  end;
end;

procedure WriteManifest();
var
  FileStream: TFileStream;
  counter, StreamPosition: integer;
  workDWORD, EntrySize, numItems: dword;

begin
  try
{$REGION 'DataServerManifest'}
      if Form1.cboManifestType.ItemIndex = 0 then // Data server
      begin
        FileStream := nil;
        try
          FileStream := TFileStream.Create(AnsiReplaceStr(ManifestList[ManifestIndex],'.txt','.mbm'), fmCreate);
        except
          on E:EFCreateError do
          begin
            Form1.Memo1.Lines.Add('  *** ERROR ***: '+ E.Message);
            ErrorFlag:=true;
            exit;
          end;
        end;
        workDWORD := $00000000;
        FileStream.Write(workDWORD,4);  // total number of objects
        numItems := Length(DataServerManifest);
        for counter := 0 to Length(DataServerManifest) - 1 do
        begin
          StreamPosition := FileStream.Position;
          if DataServerManifest[counter].Result = 'Success' then
          begin
            FileStream.WriteBuffer(workDWORD, 4); // SizeOfEntry
            WriteWideChar(DataServerManifest[counter].ClientPathAndFile, FileStream);
            WriteWideChar(DataServerManifest[counter].ServerPath, FileStream);
            WriteWideChar(DataServerManifest[counter].UncompressedFileMD5Sum, FileStream);
            WriteWideChar(DataServerManifest[counter].CompressedFileMD5Sum, FileStream);
            WriteFunkySize(DataServerManifest[counter].UncompressedSize, FileStream);
            WriteFunkySize(DataServerManifest[counter].CompressedSize, FileStream);
            FileStream.Write(workDWORD,2);
            FileStream.Write(DataServerManifest[counter].FileFlags, 4);
            EntrySize := FileStream.Position - StreamPosition - 4;
            FileStream.Seek(-(EntrySize + 4), soFromCurrent);
            FileStream.Write(EntrySize, 4);
            FileStream.Seek(0, soFromEnd);
          end
          else
          begin
            Form1.Memo1.Lines.Add(' *** Error *** - manifest line ' + IntToStr (counter + 1) + ' - ' + DataServerManifest[counter].Result);
            numItems := numItems - 1;
            ErrorFlag:=true;
          end;
        end;
        FileStream.Seek(0,soFromBeginning);
        FileStream.Write(numItems, 4);
        Form1.Memo1.Lines.Add('');
      end
{$ENDREGION}
    else
{$REGION 'AuthServerManifest'}
      if Form1.cboManifestType.ItemIndex = 1 then  // Auth server
      begin
        FileStream:= nil;
        try
          FileStream := TFileStream.Create(AnsiReplaceStr(ManifestList[ManifestIndex],'.txt','.mbam'),fmCreate);
        except
          on E:EFCreateError do
          begin
            Form1.Memo1.Lines.Add('  *** ERROR ***: '+ E.Message);
            ErrorFlag:=true;
            exit;
          end;
        end;
        for counter := 0 to Length(AuthServerManifest) - 1 do
        begin
          if AuthServerManifest[counter].Result = 'Success' then
          begin
            WriteWideChar(AuthServerManifest[counter].ClientAndServerPath, FileStream);
            WriteFunkySize(AuthServerManifest[counter].ObjectSize, FileStream);
          end
          else
          begin
            Form1.Memo1.Lines.Add(' *** Error *** - manifest line ' + IntToStr (counter + 1) + ' - ' + AuthServerManifest[counter].Result);
            ErrorFlag:=true;
          end;
        end;
        Form1.Memo1.Lines.Add('');
     end;
{$ENDREGION}
  finally
    FreeAndNil(FileStream);
  end;
end;

// thread stuff - http://edn.embarcadero.com/article/22411
function TForm1.ThreadIDToIndex( ThreadID : Cardinal ) : integer;
var Counter : integer;
begin
  Result := -1;
  for Counter := 0 to TotalThreads do
    if ThreadInfo[Counter].ThreadID = ThreadID then
    begin
      Result := Counter;
      break;
    end;
end;

procedure TForm1.ThreadMessage(var Message: TMessage);
var
  ThreadIndex: integer;
  counter: integer;
  ActiveThreads, AllClosed: boolean;
begin
  if Message.WParam = Thread_ItemCompleted then Form1.gauCurrentProgress.AddProgress(1);

  if (Message.WParam = Thread_Completed) or (Message.WParam = Thread_Stopped) then
  begin
    ThreadIndex := ThreadIDToIndex(Message.LParam);
    if (ThreadIndex <> -1) and not (ThreadInfo[ThreadIndex].Closed) then
    begin
      CloseHandle(ThreadInfo[ThreadIndex].ThreadHandle);
      ThreadInfo[ThreadIndex].Closed := true;
      ThreadInfo[ThreadIndex].Active := false;
    end;
    // Check to see if we have any more threads running, and make sure handles are closed
    ActiveThreads := false;
    AllClosed := true;
    for counter := 0 to TotalThreads do
    begin
      if ThreadInfo[counter].Active = true then ActiveThreads := true;
      if ThreadInfo[counter].Closed = false then AllClosed := false;
    end;

    if ((ActiveThreads = false) and (AllClosed = true)) then
    begin
      if StopNow then
      begin
       memo1.lines.add('*** All threads stopped. ***');
       Form1.gauCurrentProgress.Progress:=0;
       Form1.gauTotalManifests.Progress:=0;
      end;
      if not StopNow then WriteManifest();  // Write out the manifest if not stopped

      if (ManifestIndex < ManifestList.Count -1) and (not StopNow) then
      begin
        //Kick it off again
        Form1.gauCurrentProgress.Progress := 0;
        Form1.gauTotalManifests.AddProgress(1);
        ManifestIndex := ManifestIndex + 1;
        ParseManifest(ManifestList[ManifestIndex],cboManifestType.ItemIndex);
        NextManifestItem := 0;
        StartThreads();
      end
      else
      begin
        // enable controls
        if (not StopNow) then Form1.gauTotalManifests.AddProgress(1);
        btnChangePath.Enabled := true;
        pnlControls.Enabled := true;
        Memo1.Lines.Add('Completed processing at ' + TimeToStr(Now));
        if ErrorFlag then
        Memo1.Lines.add('*** Warnings and/or errors were reported.  Please scroll up and check statuses. ***');
        Memo1.Lines.Add('');
      end;
      if CloseApp = true then Close;
    end;
  end;
end;

procedure TForm1.OnCreate(Sender: TObject) ;
var
counter: integer;
begin
  InitializeCriticalSection(CriticalSection);
  ManifestList := TStringList.Create;
  ManifestList.Clear;
  TotalThreads := 7;  // zero indexed
  for counter := 0 to TotalThreads do  // set to not active and closed
  begin
    ThreadInfo[counter].Closed := true;
    ThreadInfo[counter].Active := false;
  end;
end;

procedure TForm1.OnDestroy(Sender: TObject) ;
begin
  DeleteCriticalSection(CriticalSection);
  ManifestList.Free;
end;

procedure TForm1.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
var
  counter: integer;
begin
  CloseApp := true;
  for counter := 0 to TotalThreads do
    if not ThreadInfo[counter].Closed then
    begin
     CanClose := false; // cannot close if threads are running
     StopNow := true;  //  so set StopNow so the threads will stop themselves
    end;
end;

procedure TForm1.btnChangePathClick(Sender: TObject);
Begin
  if cboManifestType.ItemIndex = 0  then
  begin
    Dir := BrowseDialog('Please select the client directory from '
                         + 'which to pull the source files (UruExplorer.exe '
                         + 'is in it).',BIF_RETURNONLYFSDIRS);
    If Dir <> '' then
    Begin
      If RightStr(Dir,1) <> '\' then Dir := Dir + '\';
      If not FileExists(Dir + 'UruExplorer.exe') then
      begin
        MessageDlg('UruExplorer.exe not found in selected ' +
        chr($0d) + chr($0a) + 'directory.  Aborting.',
        mtWarning, [mbOK], 0);
        exit;
      end;
    txtSourcePath.Text := Dir;
    End;
  end
  else  // auth manifest - no check for UruExplorer.exe is needed
  begin
    Dir := BrowseDialog('Please select the directory which contains '
                         + 'the files for this Auth server manifest.'
                         ,BIF_RETURNONLYFSDIRS);
    If RightStr(Dir,1) <> '\' then Dir := Dir + '\';
    txtSourcePath.text := Dir;
  end;
End;


procedure TForm1.btnClearClick(Sender: TObject);
begin
  Memo1.Clear;
end;

procedure TForm1.btnMakeManifestClick(Sender: TObject);
begin
  // disable controls while processing
  btnChangePath.Enabled := false;
  pnlControls.Enabled := false;

  NextManifestItem := 0;
  ManifestIndex := 0;
  Form1.gauCurrentProgress.Progress := 0;
  Form1.gauTotalManifests.Progress := 0;
  ErrorFlag:=false;
  StopNow := false;
  ManifestList.Clear;
  Memo1.Clear;
  OpenDialog1.FileName := '';
  OpenDialog1.Files.Clear;
  OpenDialog1.Title := 'Please select manifest(s) to process';
  OpenDialog1.Filter := 'Text files (*.txt)|*.txt';

  If (OpenDialog1.Execute = false) or (OpenDialog1.Files.Count = 0) then
  begin
  // enable controls
    btnChangePath.Enabled := true;
    pnlControls.Enabled := true;
    exit;
  end;

  if ((txtSourcePath.Text = '') and (cboManifestType.ItemIndex = 0)) then
  Begin
    Dir := BrowseDialog('Please select the client directory from '
                         + 'which to pull the source files (UruExplorer.exe '
                         + 'is in it).',BIF_RETURNONLYFSDIRS);
    If Dir <> '' then
    Begin
      If RightStr(Dir,1) <> '\' then Dir := Dir + '\';
      If not FileExists(Dir + 'UruExplorer.exe') then
      Begin
        MessageDlg('UruExplorer.exe not found in selected ' +
                    chr($0d) + chr($0a) + 'directory.  Aborting.',
                    mtWarning, [mbOK], 0);
        // enable controls and exit
        btnChangePath.Enabled := true;
        pnlControls.Enabled := true;
        exit;
      end;
      txtSourcePath.text := Dir;
    End
    else
    Begin
      Form1.Memo1.Lines.Add('  *** ERROR *** : Source directory not found or not selected.' +#13#10);
      MessageDlg('Directory not selected.', mtWarning, [mbOK], 0);
      // enable controls and exit
      Form1.btnChangePath.Enabled := true;
      Form1.pnlControls.Enabled := true;
      exit;
    end;
  End
  else if (cboManifestType.ItemIndex = 1) then // auth manifest - no check for UruExplorer.exe needed
  begin
    Dir := BrowseDialog('Please select the directory which contains '
                         + 'the files for this Auth server manifest.'
                         ,BIF_RETURNONLYFSDIRS);
    if Dir = '' then
    Begin
      Form1.Memo1.Lines.Add('  *** ERROR*** : Source directory not found or not selected.' +#13#10);
      MessageDlg('Directory not selected.', mtWarning, [mbOK], 0);
      // enable controls and exit
      Form1.btnChangePath.Enabled := true;
      Form1.pnlControls.Enabled := true;
      exit;
    end;
    If RightStr(Dir,1) <> '\' then Dir := Dir + '\';
    txtSourcePath.text := Dir;
  end;

  Memo1.Lines.Add('Started processing at ' + TimeToStr(Now));
  FilePath := ExtractFilePath(OpenDialog1.Files.Strings[0]);
  SourcePath := txtSourcePath.text;
  ManifestList.Assign(OpenDialog1.Files);
  ParseManifest(ManifestList[0],cboManifestType.ItemIndex);
  gauTotalManifests.MaxValue := ManifestList.Count;
  StartThreads();

end;

procedure TForm1.btnStopClick(Sender: TObject);
begin
  StopNow:=true;
  memo1.lines.add('*** Stopping all threads (this may take some time).  Please wait. ***');
end;

procedure TForm1.cboManifestTypeChange(Sender: TObject);
begin
  txtSourcePath.Text := '';  // clear source path upon manifest type change
  if cboManifestType.itemindex = 1 then
    chkOverwrite.Enabled := false
  else
    chkOverwrite.Enabled := true;
end;

procedure TForm1.chkOverwriteClick(Sender: TObject);
begin
  if chkOverwrite.Checked = true then
    OverwriteExisting := true
  else
    OverwriteExisting := false;
end;

end.

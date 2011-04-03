object Form1: TForm1
  Left = 0
  Top = 0
  BorderIcons = [biSystemMenu, biMinimize]
  BorderStyle = bsSingle
  Caption = 'Manifest Creator'
  ClientHeight = 348
  ClientWidth = 474
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  Icon.Data = {
    0000010001002020100001000400E80200001600000028000000200000004000
    0000010004000000000000000000000000000000000000000000000000000000
    00000000D2000000E6000000FF00797987006B6BC3008585F3009E9EB10073B1
    D4007EC1E8000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000009000000000000000000000000000000999000000000
    0000000000000000009899990000000000000000000000009899989000000000
    0000000000000001999989000000000000000000000000122998990000000000
    0000000000000122239990000000000000000000000012223332900000000000
    0000000000012223332200000000000000000000001222333220000000000000
    0000000001222333220000000000000000000000122233322000000000000000
    0000000122233322000000000000000000000012223332200000000000000000
    0000012223332200000000000000000000001222333220000000000000000000
    0001222333220000000000000000000000422233322000000000000000000000
    0474233322000000000000000000000047474332200000000000000000000006
    6474742200000000000000000000000566474740000000000000000000000006
    6664740000000000000000000000000056664000000000000000000000000000
    0666000000000000000000000000000000500000000000000000000000000000
    000000000000000000000000000000000000000000000000000000000000FFFF
    FFFFFFFFFFFFFFFFFFFFFFFFFFE7FFFFFF87FFFFFF0FFFFFFC0FFFFFF01FFFFF
    E03FFFFFC03FFFFF807FFFFF007FFFFE00FFFFFC01FFFFF803FFFFF007FFFFE0
    0FFFFFC01FFFFF803FFFFF007FFFFE00FFFFFC01FFFFF803FFFFF007FFFFE00F
    FFFFE01FFFFFE03FFFFFF07FFFFFF8FFFFFFFDFFFFFFFFFFFFFFFFFFFFFF}
  OldCreateOrder = False
  ShowHint = True
  OnCloseQuery = FormCloseQuery
  OnCreate = OnCreate
  OnDestroy = OnDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object lblSourcePath: TLabel
    Left = 8
    Top = 289
    Width = 154
    Height = 16
    Caption = 'Selected source files path:'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Arial'
    Font.Style = []
    ParentFont = False
  end
  object gauCurrentProgress: TGauge
    Left = 234
    Top = 279
    Width = 215
    Height = 26
    Progress = 0
  end
  object Label1: TLabel
    Left = 275
    Top = 265
    Width = 126
    Height = 13
    Caption = 'Current manifest progress'
  end
  object gauTotalManifests: TGauge
    Left = 234
    Top = 233
    Width = 215
    Height = 26
    Progress = 0
  end
  object Label2: TLabel
    Left = 276
    Top = 217
    Width = 125
    Height = 13
    Caption = 'Total manifests processed'
  end
  object Memo1: TMemo
    Left = 8
    Top = 8
    Width = 457
    Height = 169
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 0
    WordWrap = False
  end
  object btnStop: TButton
    Left = 208
    Top = 186
    Width = 89
    Height = 25
    Hint = 'Stop processing manifest'
    Caption = '&Stop processing'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
    TabOrder = 1
    OnClick = btnStopClick
  end
  object txtSourcePath: TEdit
    Left = 8
    Top = 319
    Width = 353
    Height = 21
    ReadOnly = True
    TabOrder = 2
  end
  object btnChangePath: TButton
    Left = 367
    Top = 318
    Width = 74
    Height = 23
    Caption = 'Change'
    TabOrder = 3
    OnClick = btnChangePathClick
  end
  object pnlControls: TPanel
    Left = 0
    Top = 183
    Width = 193
    Height = 82
    BevelOuter = bvNone
    TabOrder = 4
    object lblManifestType: TLabel
      Left = 13
      Top = 60
      Width = 70
      Height = 13
      Caption = 'Manifest type:'
    end
    object btnMakeManifest: TButton
      Left = 9
      Top = 3
      Width = 89
      Height = 25
      Hint = 'Mumble, mumble, mumble....'
      Caption = '&Make Manifest'
      TabOrder = 0
      OnClick = btnMakeManifestClick
    end
    object btnClear: TButton
      Left = 120
      Top = 3
      Width = 65
      Height = 25
      Hint = 'Clear the display box'
      Caption = '&Clear'
      TabOrder = 1
      OnClick = btnClearClick
    end
    object chkOverwrite: TCheckBox
      Left = 9
      Top = 34
      Width = 105
      Height = 17
      Hint = 'Overwite existing compressed files, even if timestamps match'
      Caption = 'Force overwrite'
      TabOrder = 2
      OnClick = chkOverwriteClick
    end
    object cboManifestType: TComboBox
      Left = 89
      Top = 57
      Width = 89
      Height = 21
      Hint = 'Manifest type to generate'
      ItemHeight = 13
      ItemIndex = 0
      TabOrder = 3
      Text = 'Data server'
      OnChange = cboManifestTypeChange
      Items.Strings = (
        'Data server'
        'Auth Server')
    end
  end
  object OpenDialog1: TOpenDialog
    Options = [ofAllowMultiSelect, ofPathMustExist, ofFileMustExist, ofOldStyleDialog, ofEnableSizing]
    Left = 408
    Top = 16
  end
end

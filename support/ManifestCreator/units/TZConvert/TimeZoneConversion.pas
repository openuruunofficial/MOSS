unit TimeZoneConversion;

interface

uses
  Windows, SysUtils;

function LocaleDateTimeToGMTDateTime(const Value: TDateTime) : TDateTime;

function GMTDateTimeToLocaleDateTime(const Value: TDateTime) : TDateTime;

implementation

const
  MinsPerDay = 24*60;

function GetGMTBias : Integer;
var
  info: TTimeZoneInformation;
  Mode: DWord;
begin
  Mode := GetTimeZoneInformation(info);
  Result := info.Bias;
  case Mode of
    TIME_ZONE_ID_INVALID:
    begin
      RaiseLastWin32Error
    end;
    TIME_ZONE_ID_STANDARD:
    begin
      Result := Result+info.StandardBias
    end;
    TIME_ZONE_ID_DAYLIGHT:
    begin
      Result := Result+info.DaylightBias
    end;
  end;
end;

function LocaleDateTimeToGMTDateTime(const Value: TDateTime) : TDateTime;
begin
  Result := Value+(GetGMTBias/MinsPerDay);
end;

function GMTDateTimeToLocaleDateTime(const Value: TDateTime) : TDateTime;
begin
  Result := Value-(GetGMTBias/MinsPerDay);
end;

end.
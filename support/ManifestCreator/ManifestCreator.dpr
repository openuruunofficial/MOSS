program ManifestCreator;

uses
  Forms,
  Main in 'Main.pas' {Form1};

{$R *.res}
{$R mc.res}

begin
  Application.Initialize;
  Application.Title := 'Manifest Creator';
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.

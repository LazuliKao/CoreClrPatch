#r "nuget: SharpPdb, 1.0.4"
open System.IO

let offset = (-1024 + 4096);

let fetch(str:string):(string*SharpPdb.Native.PdbPublicSymbol) list=
    let mutable result:(string*SharpPdb.Native.PdbPublicSymbol) list=[]
    for dir in "coreclr"|>Path.GetFullPath|>Directory.GetDirectories do
        let mutable found =false
        printfn "dir : %s" dir
        let dll = Path.Combine(dir,"coreclr.dll")
        let pdb = Path.Combine(dir,"coreclr.pdb")
        using (new SharpPdb.Native.PdbFileReader(pdb)) (fun pdb->
            for item in pdb.PublicSymbols do
                if item.Name.Contains(str) then
                    printfn "Find : %s" item.Name 
                    printfn "RVA : %d" item.RelativeVirtualAddress 
                    result<-(dll,item)::result
                    if found then 
                        printfn "Found duplicate"
                        System.Console.ReadKey()|>ignore
                    found<-true
        )
    result
let generate(found:(string*SharpPdb.Native.PdbPublicSymbol)list)=
    let mutable temple:byte[]=[||]
    let mutable samples:byte[] list=[]
    for (dll,item) in found do
        let target=(int)item.RelativeVirtualAddress - offset
        let bytes=dll|>File.ReadAllBytes
        printfn "Signature of %s: " (dll|>Path.GetDirectoryName|>Path.GetFileName)
        let res=bytes.[target..target+127]
        for b in res do
            printf "%s " (b.ToString("X2"))
        printfn ""
        if temple.Length=0 then
            temple<-res
        else
            samples<-res::samples
    let mutable templeStr:string[]=[|
        for b in temple do
            b.ToString("X2")
    |]
    for sample in samples do
        for i = 0 to 127 do
            if temple.[i] <> sample.[i] then
                templeStr.[i] <- "?";
    printfn "combined result"
    for v in templeStr do
        printf "%s " v
    printfn ""
    
generate (fetch "LogInfoForFatalError")
generate (fetch "LogFatalError")


    
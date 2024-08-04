$assemblies=(
       "System"
)

$source=@"
using System;
namespace Helloworld
{
       public static class Hello{
             public static void Main(){
                    Console.WriteLine("Hello, world!");
             }
       }
}
"@

Add-Type -ReferencedAssemblies $assemblies -TypeDefinition $source -Language CSharp

[HelloWorld.Hello]::Main()

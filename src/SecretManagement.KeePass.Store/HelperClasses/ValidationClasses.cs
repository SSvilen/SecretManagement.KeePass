using System.Management.Automation;

namespace ValidationClasses {
    class ValidateFileNotExists : ValidateArgumentsAttribute {
        protected override void Validate(object arguments, EngineIntrinsics engineIntrinsics) {
           if(System.IO.File.Exists(arguments as string)) {
                throw new ValidationMetadataException($"The specified file {arguments} already exists!");
           }
        }
    }
}

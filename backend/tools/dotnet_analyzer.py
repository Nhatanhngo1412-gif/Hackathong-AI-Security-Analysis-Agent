"""Analyzer for .NET assemblies using dnfile."""

from typing import Optional


class DotNetAnalyzer:
    """Analyze .NET assemblies - extract metadata, types, methods."""

    @staticmethod
    def analyze(file_path: str) -> dict:
        try:
            import dnfile
            dn = dnfile.dnPE(file_path)
        except ImportError:
            return {"error": "dnfile not installed"}
        except Exception as e:
            return {"error": f"Not a valid .NET assembly: {e}"}

        result = {
            "is_dotnet": True,
            "file_path": file_path,
        }

        try:
            if hasattr(dn, "net") and dn.net:
                if hasattr(dn.net, "metadata") and dn.net.metadata:
                    result["metadata_version"] = str(getattr(dn.net.metadata, "Version", "unknown"))

                if hasattr(dn.net, "Flags"):
                    result["flags"] = hex(dn.net.Flags.value) if hasattr(dn.net.Flags, "value") else str(dn.net.Flags)

                strings_heap = []
                if hasattr(dn.net, "metadata") and hasattr(dn.net.metadata, "streams"):
                    for stream in dn.net.metadata.streams:
                        if hasattr(stream, "name") and stream.name == "#Strings":
                            pass

                types = DotNetAnalyzer._get_type_defs(dn)
                result["types"] = types[:100]
                result["total_types"] = len(types)

                methods = DotNetAnalyzer._get_methods(dn)
                result["methods"] = methods[:200]
                result["total_methods"] = len(methods)

                references = DotNetAnalyzer._get_assembly_refs(dn)
                result["assembly_references"] = references

                module_refs = DotNetAnalyzer._get_module_refs(dn)
                result["module_references"] = module_refs

                type_refs = DotNetAnalyzer._get_type_refs(dn)
                result["type_references"] = type_refs[:100]
                result["total_type_references"] = len(type_refs)
        except Exception as e:
            result["parse_warning"] = str(e)

        dn.close()
        return result

    @staticmethod
    def _get_type_defs(dn) -> list:
        types = []
        try:
            if hasattr(dn.net.mdtables, "TypeDef") and dn.net.mdtables.TypeDef:
                for row in dn.net.mdtables.TypeDef.rows:
                    name = str(row.TypeName) if row.TypeName else ""
                    namespace = str(row.TypeNamespace) if row.TypeNamespace else ""
                    full_name = f"{namespace}.{name}" if namespace else name
                    if name and name != "<Module>":
                        types.append(full_name)
        except Exception:
            pass
        return types

    @staticmethod
    def _get_methods(dn) -> list:
        methods = []
        try:
            if hasattr(dn.net.mdtables, "MethodDef") and dn.net.mdtables.MethodDef:
                for row in dn.net.mdtables.MethodDef.rows:
                    name = str(row.Name) if row.Name else ""
                    if name:
                        methods.append(name)
        except Exception:
            pass
        return methods

    @staticmethod
    def _get_assembly_refs(dn) -> list:
        refs = []
        try:
            if hasattr(dn.net.mdtables, "AssemblyRef") and dn.net.mdtables.AssemblyRef:
                for row in dn.net.mdtables.AssemblyRef.rows:
                    name = str(row.Name) if row.Name else ""
                    if name:
                        refs.append(name)
        except Exception:
            pass
        return refs

    @staticmethod
    def _get_module_refs(dn) -> list:
        refs = []
        try:
            if hasattr(dn.net.mdtables, "ModuleRef") and dn.net.mdtables.ModuleRef:
                for row in dn.net.mdtables.ModuleRef.rows:
                    name = str(row.Name) if row.Name else ""
                    if name:
                        refs.append(name)
        except Exception:
            pass
        return refs

    @staticmethod
    def _get_type_refs(dn) -> list:
        refs = []
        try:
            if hasattr(dn.net.mdtables, "TypeRef") and dn.net.mdtables.TypeRef:
                for row in dn.net.mdtables.TypeRef.rows:
                    name = str(row.TypeName) if row.TypeName else ""
                    namespace = str(row.TypeNamespace) if row.TypeNamespace else ""
                    full_name = f"{namespace}.{name}" if namespace else name
                    if name:
                        refs.append(full_name)
        except Exception:
            pass
        return refs

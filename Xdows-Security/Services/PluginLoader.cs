using Microsoft.UI.Xaml;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Threading;
using Xdows_Security.PluginsLoader;

namespace Xdows_Security.Services
{
    public class PluginLoader : IDisposable
    {
        public string PluginDirectory { get; }
        private readonly ConcurrentDictionary<string, Lazy<IPlugin>> _pluginCache = new();
        private readonly ConcurrentDictionary<string, PluginLoadContext> _loadContexts = new();
        private readonly ReaderWriterLockSlim _lock = new();
        private bool _isDisposed;

        public PluginLoader(string? pluginDirectory = null)
        {
            PluginDirectory = pluginDirectory ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Plugins");
            if (!Directory.Exists(PluginDirectory)) Directory.CreateDirectory(PluginDirectory);
        }

        [RequiresUnreferencedCode("Plugin loading uses reflection which is not compatible with trimming")]
        [RequiresDynamicCode("Plugin loading uses reflection which requires dynamic code")]
        public IEnumerable<IPlugin> LoadPlugins(object? host = null)
        {
            var list = new List<IPlugin>();
            var hostObject = host ?? Application.Current;

            _lock.EnterReadLock();
            try
            {
                LoadBuiltInPlugins(list, hostObject);
                LoadExternalPlugins(list, hostObject);
            }
            finally
            {
                _lock.ExitReadLock();
            }

            return list;
        }

        [RequiresUnreferencedCode("Plugin loading uses reflection")]
        [RequiresDynamicCode("Plugin loading requires dynamic code")]
        private void LoadBuiltInPlugins(List<IPlugin> list, object host)
        {
            try
            {
                var loaded = AppDomain.CurrentDomain.GetAssemblies()
                    .Where(a => !a.IsDynamic && !string.IsNullOrEmpty(a.Location));

                foreach (var asm in loaded)
                {
                    try
                    {
                        var pluginTypes = asm.GetTypes()
                            .Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface);

                        foreach (var type in pluginTypes)
                        {
                            var pluginId = $"{asm.GetName().Name}:{type.FullName}";
                            
                            var lazyPlugin = _pluginCache.GetOrAdd(pluginId, _ => new Lazy<IPlugin>(() =>
                            {
                                try
                                {
                                    if (Activator.CreateInstance(type) is IPlugin plugin)
                                    {
                                        plugin.Initialize(host);
                                        return plugin;
                                    }
                                }
                                catch { }
                                return null!;
                            }, LazyThreadSafetyMode.ExecutionAndPublication));

                            if (lazyPlugin.Value != null)
                            {
                                list.Add(lazyPlugin.Value);
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        [RequiresUnreferencedCode("Plugin loading uses reflection")]
        [RequiresDynamicCode("Plugin loading requires dynamic code")]
        private void LoadExternalPlugins(List<IPlugin> list, object host)
        {
            try
            {
                var dlls = Directory.GetFiles(PluginDirectory, "*.dll", SearchOption.TopDirectoryOnly);
                
                foreach (var dll in dlls)
                {
                    try
                    {
                        var pluginId = Path.GetFileNameWithoutExtension(dll);
                        
                        var lazyPlugin = _pluginCache.GetOrAdd(pluginId, _ => new Lazy<IPlugin>(() =>
                        {
                            try
                            {
                                var context = new PluginLoadContext(dll);
                                _loadContexts[pluginId] = context;
                                
                                var assemblyName = new AssemblyName(Path.GetFileNameWithoutExtension(dll));
                                var asm = context.LoadFromAssemblyName(assemblyName);
                                
                                var pluginType = asm.GetTypes()
                                    .FirstOrDefault(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsAbstract);

                                if (pluginType != null)
                                {
                                    if (Activator.CreateInstance(pluginType) is IPlugin plugin)
                                    {
                                        plugin.Initialize(host);
                                        return plugin;
                                    }
                                }
                            }
                            catch { }
                            return null!;
                        }, LazyThreadSafetyMode.ExecutionAndPublication));

                        if (lazyPlugin.Value != null)
                        {
                            list.Add(lazyPlugin.Value);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        public bool UnloadPlugin(string pluginId)
        {
            _lock.EnterWriteLock();
            try
            {
                if (_pluginCache.TryRemove(pluginId, out _))
                {
                    if (_loadContexts.TryRemove(pluginId, out var context))
                    {
                        context.Unload();
                        return true;
                    }
                }
                return false;
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        public void ClearCache()
        {
            _lock.EnterWriteLock();
            try
            {
                foreach (var context in _loadContexts.Values)
                {
                    try { context.Unload(); } catch { }
                }
                _loadContexts.Clear();
                _pluginCache.Clear();
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            
            ClearCache();
            _lock.Dispose();
            _isDisposed = true;
        }
    }

    public class PluginLoadContext : AssemblyLoadContext
    {
        private readonly AssemblyDependencyResolver _resolver;

        public PluginLoadContext(string pluginPath) : base(isCollectible: true)
        {
            _resolver = new AssemblyDependencyResolver(pluginPath);
        }

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            var assemblyPath = _resolver.ResolveAssemblyToPath(assemblyName);
            if (assemblyPath != null)
            {
                return LoadFromAssemblyPath(assemblyPath);
            }
            return null;
        }

        protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
        {
            var libraryPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
            if (libraryPath != null)
            {
                return LoadUnmanagedDllFromPath(libraryPath);
            }
            return IntPtr.Zero;
        }
    }
}

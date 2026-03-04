/**
 * Worker Plugin Loader
 * 
 * Discovers and loads custom feed worker plugins from the plugins directory.
 * Supports hot-reload in development mode.
 */

import { EventEmitter } from 'events';
import { readdirSync, statSync, watchFile, unwatchFile } from 'fs';
import { join, basename } from 'path';

// ============================================================================
// Types
// ============================================================================

export interface PluginManifest {
    name: string;
    version: string;
    description?: string;
    author?: string;
    main: string;           // Entry point file
    schedule?: string;      // Cron expression or interval
    enabled?: boolean;
}

export interface PluginContext {
    logger: {
        info: (msg: string) => void;
        warn: (msg: string) => void;
        error: (msg: string) => void;
        debug: (msg: string) => void;
    };
    config: Record<string, unknown>;
    emit: (event: string, data: unknown) => void;
}

export interface FeedPlugin {
    name: string;
    version: string;

    // Lifecycle hooks
    initialize?(ctx: PluginContext): Promise<void>;
    destroy?(): Promise<void>;

    // Feed methods
    fetch(ctx: PluginContext): Promise<unknown[]>;
    transform?(data: unknown[]): unknown[];
    validate?(item: unknown): boolean;
    store?(items: unknown[]): Promise<number>;
}

export interface LoadedPlugin {
    manifest: PluginManifest;
    instance: FeedPlugin;
    path: string;
    loadedAt: Date;
}

// ============================================================================
// Plugin Loader
// ============================================================================

export class PluginLoader extends EventEmitter {
    private plugins: Map<string, LoadedPlugin> = new Map();
    private pluginsDir: string;
    private watching: boolean = false;

    constructor(pluginsDir: string = './plugins') {
        super();
        this.pluginsDir = pluginsDir;
    }

    /**
     * Discover and load all plugins from the plugins directory
     */
    async loadAll(): Promise<LoadedPlugin[]> {
        const loaded: LoadedPlugin[] = [];

        try {
            const entries = readdirSync(this.pluginsDir);

            for (const entry of entries) {
                const pluginPath = join(this.pluginsDir, entry);
                const stat = statSync(pluginPath);

                if (stat.isDirectory()) {
                    try {
                        const plugin = await this.loadPlugin(pluginPath);
                        if (plugin) {
                            loaded.push(plugin);
                        }
                    } catch (error) {
                        console.error(`[PluginLoader] Failed to load plugin ${entry}:`, error);
                        this.emit('error', { plugin: entry, error });
                    }
                }
            }
        } catch (error) {
            // Plugins directory doesn't exist - that's OK
            console.log('[PluginLoader] No plugins directory found, skipping plugin loading');
        }

        console.log(`[PluginLoader] Loaded ${loaded.length} plugins`);
        return loaded;
    }

    /**
     * Load a single plugin from a directory
     */
    async loadPlugin(pluginPath: string): Promise<LoadedPlugin | null> {
        const manifestPath = join(pluginPath, 'manifest.json');
        const pluginName = basename(pluginPath);

        try {
            // Load manifest using fs
            const { readFileSync } = await import('fs');
            const manifestContent = readFileSync(manifestPath, 'utf-8');
            const manifest: PluginManifest = JSON.parse(manifestContent);

            // Skip disabled plugins
            if (manifest.enabled === false) {
                console.log(`[PluginLoader] Skipping disabled plugin: ${manifest.name}`);
                return null;
            }

            // Load main entry point
            const mainPath = join(pluginPath, manifest.main);
            const pluginModule = await import(mainPath);
            const instance: FeedPlugin = pluginModule.default || pluginModule;

            // Validate plugin interface
            if (typeof instance.fetch !== 'function') {
                throw new Error(`Plugin ${manifest.name} must implement fetch() method`);
            }

            const loadedPlugin: LoadedPlugin = {
                manifest,
                instance,
                path: pluginPath,
                loadedAt: new Date(),
            };

            // Store in registry
            this.plugins.set(manifest.name, loadedPlugin);

            console.log(`[PluginLoader] Loaded plugin: ${manifest.name} v${manifest.version}`);
            this.emit('loaded', loadedPlugin);

            return loadedPlugin;
        } catch (error) {
            console.error(`[PluginLoader] Error loading plugin ${pluginName}:`, error);
            return null;
        }
    }

    /**
     * Unload a plugin by name
     */
    async unloadPlugin(name: string): Promise<boolean> {
        const plugin = this.plugins.get(name);
        if (!plugin) {
            return false;
        }

        try {
            // Call destroy hook if available
            if (plugin.instance.destroy) {
                await plugin.instance.destroy();
            }

            this.plugins.delete(name);
            this.emit('unloaded', { name });
            console.log(`[PluginLoader] Unloaded plugin: ${name}`);
            return true;
        } catch (error) {
            console.error(`[PluginLoader] Error unloading plugin ${name}:`, error);
            return false;
        }
    }

    /**
     * Reload a plugin
     */
    async reloadPlugin(name: string): Promise<LoadedPlugin | null> {
        const existing = this.plugins.get(name);
        if (!existing) {
            return null;
        }

        await this.unloadPlugin(name);

        // Clear module cache for hot reload
        const mainPath = join(existing.path, existing.manifest.main);
        delete require.cache[require.resolve(mainPath)];

        return this.loadPlugin(existing.path);
    }

    /**
     * Enable file watching for hot reload (development mode)
     */
    enableHotReload(): void {
        if (this.watching) return;

        this.watching = true;
        console.log('[PluginLoader] Hot reload enabled');

        for (const [name, plugin] of this.plugins) {
            const manifestPath = join(plugin.path, 'manifest.json');
            const mainPath = join(plugin.path, plugin.manifest.main);

            // Watch manifest
            watchFile(manifestPath, { interval: 1000 }, async () => {
                console.log(`[PluginLoader] Manifest changed for ${name}, reloading...`);
                await this.reloadPlugin(name);
            });

            // Watch main file
            watchFile(mainPath, { interval: 1000 }, async () => {
                console.log(`[PluginLoader] Source changed for ${name}, reloading...`);
                await this.reloadPlugin(name);
            });
        }
    }

    /**
     * Disable file watching
     */
    disableHotReload(): void {
        if (!this.watching) return;

        this.watching = false;

        for (const plugin of this.plugins.values()) {
            const manifestPath = join(plugin.path, 'manifest.json');
            const mainPath = join(plugin.path, plugin.manifest.main);
            unwatchFile(manifestPath);
            unwatchFile(mainPath);
        }

        console.log('[PluginLoader] Hot reload disabled');
    }

    /**
     * Get a loaded plugin by name
     */
    get(name: string): LoadedPlugin | undefined {
        return this.plugins.get(name);
    }

    /**
     * Get all loaded plugins
     */
    getAll(): LoadedPlugin[] {
        return Array.from(this.plugins.values());
    }

    /**
     * Get loaded plugin count
     */
    get count(): number {
        return this.plugins.size;
    }

    /**
     * Execute a plugin's fetch method with context
     */
    async executePlugin(name: string, config: Record<string, unknown> = {}): Promise<unknown[]> {
        const plugin = this.plugins.get(name);
        if (!plugin) {
            throw new Error(`Plugin ${name} not found`);
        }

        const context: PluginContext = {
            logger: {
                info: (msg) => console.log(`[${name}] ${msg}`),
                warn: (msg) => console.warn(`[${name}] ${msg}`),
                error: (msg) => console.error(`[${name}] ${msg}`),
                debug: (msg) => console.debug(`[${name}] ${msg}`),
            },
            config,
            emit: (event, data) => this.emit(`plugin:${name}:${event}`, data),
        };

        try {
            // Initialize if needed
            if (plugin.instance.initialize) {
                await plugin.instance.initialize(context);
            }

            // Fetch data
            let data = await plugin.instance.fetch(context);

            // Transform if available
            if (plugin.instance.transform) {
                data = plugin.instance.transform(data);
            }

            // Validate if available
            if (plugin.instance.validate) {
                data = data.filter(item => plugin.instance.validate!(item));
            }

            // Store if available
            if (plugin.instance.store) {
                const stored = await plugin.instance.store(data);
                context.logger.info(`Stored ${stored} items`);
            }

            return data;
        } catch (error) {
            context.logger.error(`Execution failed: ${error}`);
            throw error;
        }
    }
}

// Singleton instance
export const pluginLoader = new PluginLoader(
    process.env.PLUGINS_DIR || './plugins'
);

export default pluginLoader;

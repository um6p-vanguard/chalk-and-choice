import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

// Access webpack.container in ESM mode
const require = createRequire(import.meta.url);
const { container } = require('webpack');
const { ModuleFederationPlugin } = container;

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default {
  entry: './src/index.ts',
  output: {
    path: path.resolve(__dirname, '../static/jlite/extensions/chalk-lite-sync'),
    publicPath: 'auto',
    filename: '[name].js',
    library: { type: 'module' }
  },
  experiments: { outputModule: true },
  mode: 'production',
  devtool: false,
  module: {
    rules: [
      { test: /\.ts$/, use: 'ts-loader', exclude: /node_modules/ },
      { test: /\.css$/i, use: ['style-loader', 'css-loader'] },
      { test: /\.svg$/i, type: 'asset/source' },
      { test: /\.(woff2?|ttf|eot|png|jpg|gif)$/i, type: 'asset' }
    ]
  },
  resolve: { extensions: ['.ts', '.js'] },
  plugins: [
    new ModuleFederationPlugin({
      // ⚠️ use a valid JS identifier (no dashes)
      name: 'chalk_lite_sync',
      // make the remote an ES module (works with JupyterLite)
      library: { type: 'module' },
      filename: 'remoteEntry.js',
      exposes: {
        './extension': './src/index'
      },
      shared: {
        '@jupyterlab/application': { singleton: true, requiredVersion: '^4.2.0' },
        '@jupyterlab/apputils': { singleton: true, requiredVersion: '^4.2.0' },
        '@jupyterlab/notebook': { singleton: true, requiredVersion: '^4.2.0' },
        '@jupyterlab/docmanager': { singleton: true, requiredVersion: '^4.2.0' },
        '@jupyterlab/docregistry': { singleton: true, requiredVersion: '^4.2.0' },
        '@jupyterlab/nbformat': { singleton: true, requiredVersion: '^4.2.0' },
        '@jupyterlab/services': { singleton: true, requiredVersion: '^7.2.0' },
        '@lumino/coreutils': { singleton: true },
        '@lumino/signaling': { singleton: true },
        '@lumino/widgets': { singleton: true }
      }
    })
  ]
};

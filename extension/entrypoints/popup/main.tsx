import { render } from 'preact';
import '../../ui/tokens.css';
import '../../ui/ui.css';
import { watchSettings } from '../../ui/store';
import { App } from '../../ui/popup';

watchSettings();
render(<App />, document.getElementById('app')!);

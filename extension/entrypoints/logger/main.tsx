import { render } from 'preact';
import '../../ui/tokens.css';
import '../../ui/ui.css';
import { watchSettings } from '../../ui/store';
import { Logger } from '../../ui/logger';

watchSettings();
render(<Logger />, document.getElementById('app')!);

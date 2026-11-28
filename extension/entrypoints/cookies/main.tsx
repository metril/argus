import { render } from 'preact';
import '../../ui/tokens.css';
import '../../ui/ui.css';
import '../../ui/cookies.css';
import { watchSettings } from '../../ui/store';
import { CookiesPage } from '../../ui/cookies/Page';

watchSettings();
render(<CookiesPage />, document.getElementById('app')!);

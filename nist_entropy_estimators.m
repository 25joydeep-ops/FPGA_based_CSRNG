% =========================================================================
% NIST SP 800-90B Entropy Estimators for Chaotic Bitstream
% =========================================================================
% Runs 5 entropy estimators on the Method B (12-bit ADS1015) bitstream.
% Each estimator computes an entropy-per-bit value (0 to 1).
% The final reported min-entropy is the MINIMUM across all estimators —
% this is the most conservative and cryptographically correct measure.
%
% Estimators included:
%   1. Most Common Value Estimator
%   2. Collision Estimator
%   3. Markov Estimator
%   4. Compression Estimator
%   5. Lag Prediction Estimator
%
% Final output tells you:
%   - Min-entropy per bit (H_min)
%   - How many raw bits needed per SHA-256 call (256 / H_min)
%   - Whether your bitstream qualifies for CSRNG seeding
% =========================================================================

clc; clear; close all;

%% ── 1. LOAD BITSTREAM ────────────────────────────────────────────────────

filename = 'H2.txt';

fid  = fopen(filename, 'r');
raw  = fread(fid, '*char')';
fclose(fid);

bits = double(raw == '1');
n    = length(bits);

fprintf('=================================================================\n');
fprintf('         NIST SP 800-90B Entropy Estimators\n');
fprintf('=================================================================\n');
fprintf('  Bitstream  : %s\n', filename);
fprintf('  Total bits : %d\n', n);
fprintf('  Ones       : %d  (%.2f%%)\n', sum(bits), 100*sum(bits)/n);
fprintf('  Zeros      : %d  (%.2f%%)\n', sum(~bits), 100*sum(~bits)/n);
fprintf('=================================================================\n\n');

% Storage for all estimator results
estimator_names  = {};
entropy_values   = [];

%% ── ESTIMATOR 1: MOST COMMON VALUE ───────────────────────────────────────
% The most basic estimator. Finds the most frequent symbol (0 or 1)
% and computes entropy assuming an attacker always guesses that symbol.
% Directly penalises DC bias from your chaotic circuit.
%
% If p_max = probability of most common bit:
%   H = -log2(p_max)
% Perfect balance (50/50) → H = 1.0 bit
% Severe bias (90/10)     → H = 0.152 bits

p_ones  = sum(bits) / n;
p_zeros = 1 - p_ones;
p_max   = max(p_ones, p_zeros);

% Upper bound using Wilson interval for confidence
z        = 2.576;    % 99.5% confidence
p_max_ub = min(1, p_max + z * sqrt(p_max*(1-p_max)/n));
H_mcv    = -log2(p_max_ub);

estimator_names{end+1} = 'Most Common Value';
entropy_values(end+1)  = H_mcv;

fprintf('── Estimator 1: Most Common Value ───────────────────────────────\n');
fprintf('  P(ones) = %.4f | P(zeros) = %.4f\n', p_ones, p_zeros);
fprintf('  p_max = %.4f | p_max_upper_bound = %.4f\n', p_max, p_max_ub);
fprintf('  H_mcv = %.6f bits/bit\n\n', H_mcv);

%% ── ESTIMATOR 2: COLLISION ESTIMATOR ─────────────────────────────────────
% Measures how quickly repeated patterns appear in the bitstream.
% A random source takes longer to produce collisions than a biased
% or correlated source.
% Particularly sensitive to deterministic structure in chaotic signals.
%
% Splits sequence into non-overlapping blocks, finds the shortest
% prefix of each block that has appeared before (collision length t_i).

block_size = min(512, floor(n/4));   % use quarter of data as reference
Q          = floor(n / 2);           % use second half for testing
L_block    = 7;                      % substring length to search

% Use first Q bits as dictionary, search in next Q bits
dict_bits  = bits(1:Q);
test_bits  = bits(Q+1:end);
n_test     = length(test_bits);

% Find collision lengths
t_values = [];
i = 1;
while i <= n_test - L_block
    substr = test_bits(i:i+L_block-1);
    found  = false;
    for j = 1:Q-L_block+1
        if all(dict_bits(j:j+L_block-1) == substr)
            t_values(end+1) = L_block;
            found = true;
            break;
        end
    end
    if ~found
        t_values(end+1) = L_block + 1;   % no collision found within block
    end
    i = i + L_block;
    if length(t_values) >= 200, break; end   % cap for speed
end

if length(t_values) < 5
    H_col = NaN;
    fprintf('── Estimator 2: Collision ────────────────────────────────────────\n');
    fprintf('  Insufficient collisions found. Skipping.\n\n');
else
    mu_t  = mean(t_values);
    sig_t = std(t_values);
    n_col = length(t_values);

    % NIST SP 800-90B collision entropy formula
    z_val = 2.576;   % 99% one-sided
    mu_lb = mu_t - z_val * sig_t / sqrt(n_col);   % lower bound on mean
    H_col = max(0, min(1, log2(mu_lb) / 1));       % entropy estimate

    estimator_names{end+1} = 'Collision';
    entropy_values(end+1)  = H_col;

    fprintf('── Estimator 2: Collision ────────────────────────────────────────\n');
    fprintf('  Collision samples: %d | mean(t) = %.4f | std(t) = %.4f\n', ...
            n_col, mu_t, sig_t);
    fprintf('  H_col = %.6f bits/bit\n\n', H_col);
end

%% ── ESTIMATOR 3: MARKOV ESTIMATOR ────────────────────────────────────────
% Models the probability that a bit is 0 or 1 given the previous bit.
% This is the most critical estimator for your chaos circuit because
% consecutive chaotic samples are often correlated — the signal state
% at time t influences the state at time t+1 through the underlying
% differential equations.
%
% Builds a first-order Markov transition matrix:
%   P(0→0), P(0→1), P(1→0), P(1→1)
% Then estimates entropy from the worst-case transition path.

% Count transitions
T = zeros(2, 2);   % T(i,j) = count of transition from i to j (0-indexed+1)
for i = 1:n-1
    from = bits(i) + 1;
    to   = bits(i+1) + 1;
    T(from, to) = T(from, to) + 1;
end

% Transition probabilities
P_trans = T ./ sum(T, 2);   % row-normalised

% Initial state probabilities
p0_init = sum(bits == 0) / n;
p1_init = sum(bits == 1) / n;

% Entropy of the Markov chain (worst-case path over L steps)
L_markov = min(128, floor(n/10));

% Forward probability computation over L steps
% Track the min-entropy path
p_state = [p0_init, p1_init];
log_p_min_path = 0;

for step = 1:L_markov
    % Most likely next state from each current state
    p_next = p_state * P_trans;
    % Worst case: probability of most likely L-bit sequence
    p_max_trans = max(P_trans, [], 2)';
    log_p_min_path = log_p_min_path + log2(max(p_state .* p_max_trans));
    p_state = p_next / sum(p_next);
end

H_markov = max(0, -log_p_min_path / L_markov);
H_markov = min(1, H_markov);   % cap at 1

estimator_names{end+1} = 'Markov';
entropy_values(end+1)  = H_markov;

fprintf('── Estimator 3: Markov ───────────────────────────────────────────\n');
fprintf('  Transition matrix (rows=from, cols=to):\n');
fprintf('    P(0→0)=%.4f  P(0→1)=%.4f\n', P_trans(1,1), P_trans(1,2));
fprintf('    P(1→0)=%.4f  P(1→1)=%.4f\n', P_trans(2,1), P_trans(2,2));
fprintf('  Path length L=%d | H_markov = %.6f bits/bit\n\n', L_markov, H_markov);

%% ── ESTIMATOR 4: COMPRESSION ESTIMATOR ──────────────────────────────────
% Applies LZ77-style compression logic to the bitstream.
% A truly random source cannot be compressed — its LZ complexity
% approaches the theoretical maximum.
% If your chaos bits compress well, hidden patterns are present.
%
% Uses the Lempel-Ziv complexity measure: counts the number of distinct
% substrings needed to parse the sequence from left to right.

% LZ76 complexity
parsed    = {};
i         = 1;
w         = '';
lz_count  = 0;

while i <= n
    c = num2str(bits(i));
    wc = [w, c];
    % Check if wc has appeared before in parsed set
    if ~any(strcmp(parsed, wc))
        parsed{end+1} = wc;
        lz_count = lz_count + 1;
        w = '';
    else
        w = wc;
    end
    i = i + 1;
end
if ~isempty(w)
    lz_count = lz_count + 1;
end

% Theoretical LZ complexity for a random binary sequence of length n
lz_random = n / log2(n);

% Compression ratio (1.0 = incompressible = random, <1.0 = compressible)
lz_ratio  = lz_count / lz_random;
H_comp    = min(1, max(0, lz_ratio));

estimator_names{end+1} = 'Compression (LZ)';
entropy_values(end+1)  = H_comp;

fprintf('── Estimator 4: Compression (LZ76) ──────────────────────────────\n');
fprintf('  LZ complexity : %d phrases\n', lz_count);
fprintf('  Random expect : %.1f phrases\n', lz_random);
fprintf('  LZ ratio      : %.4f (1.0 = fully random)\n', lz_ratio);
fprintf('  H_comp        = %.6f bits/bit\n\n', H_comp);

%% ── ESTIMATOR 5: LAG PREDICTION ESTIMATOR ────────────────────────────────
% Tests whether knowing a bit from k steps ago helps predict the current bit.
% Directly targets temporal correlations introduced by the chaotic circuit's
% underlying differential equations — a unique weakness of analog chaos sources
% that simpler estimators can miss.
%
% For each lag k, trains the best predictor and measures its accuracy.
% Entropy is derived from the worst-case (best predictor) accuracy.

max_lag    = min(10, floor(n/20));
best_acc   = 0;   % highest prediction accuracy across all lags

fprintf('── Estimator 5: Lag Prediction ──────────────────────────────────\n');

for k = 1:max_lag
    % For each lag, build simple predictor: predict bit(t) from bit(t-k)
    x_lag  = bits(1:end-k);
    y_curr = bits(k+1:end);
    n_lag  = length(y_curr);

    % Count correct predictions for each rule: predict 0 or 1 from lag bit
    correct_0_from_0 = sum(y_curr(x_lag==0) == 0);
    correct_1_from_0 = sum(y_curr(x_lag==0) == 1);
    correct_0_from_1 = sum(y_curr(x_lag==1) == 0);
    correct_1_from_1 = sum(y_curr(x_lag==1) == 1);

    % Best predictor: for each lag value, predict the most common outcome
    n_from_0 = sum(x_lag == 0);
    n_from_1 = sum(x_lag == 1);

    correct = max(correct_0_from_0, correct_1_from_0) + ...
              max(correct_0_from_1, correct_1_from_1);
    acc = correct / n_lag;

    if acc > best_acc
        best_acc     = acc;
        best_lag     = k;
    end
    fprintf('  Lag k=%-3d | Prediction accuracy = %.4f\n', k, acc);
end

% Entropy from best predictor accuracy (NIST 800-90B formula)
% Upper bound on accuracy with confidence correction
z_lag    = 2.576;
acc_ub   = min(1, best_acc + z_lag * sqrt(best_acc*(1-best_acc)/n));
H_lag    = max(0, -log2(acc_ub));

estimator_names{end+1} = 'Lag Prediction';
entropy_values(end+1)  = H_lag;

fprintf('  → Best accuracy: %.4f at lag k=%d\n', best_acc, best_lag);
fprintf('  H_lag = %.6f bits/bit\n\n', H_lag);

%% ── FINAL MIN-ENTROPY REPORT ─────────────────────────────────────────────

fprintf('=================================================================\n');
fprintf('                 ENTROPY ESTIMATION SUMMARY\n');
fprintf('=================================================================\n');
fprintf('  %-30s  %s\n', 'Estimator', 'H (bits/bit)');
fprintf('  %s\n', repmat('-', 1, 50));

valid_mask = ~isnan(entropy_values);
for i = 1:length(estimator_names)
    if valid_mask(i)
        flag = '';
        if entropy_values(i) == min(entropy_values(valid_mask))
            flag = '  ← MIN (used for CSRNG sizing)';
        end
        fprintf('  %-30s  %.6f%s\n', estimator_names{i}, entropy_values(i), flag);
    else
        fprintf('  %-30s  N/A\n', estimator_names{i});
    end
end

H_min = min(entropy_values(valid_mask));

fprintf('  %s\n', repmat('-', 1, 50));
fprintf('  Min-Entropy (H_min)           = %.6f bits/bit\n\n', H_min);

% How many raw bits needed per SHA-256 call
bits_needed_256 = ceil(256 / H_min);
bits_needed_128 = ceil(128 / H_min);

fprintf('  For 256-bit SHA-256 security  → need %d raw bits per call\n', bits_needed_256);
fprintf('  For 128-bit security level    → need %d raw bits per call\n', bits_needed_128);
fprintf('  Your current bitstream length → %d bits\n', n);
fprintf('  SHA-256 calls possible        → %d calls\n\n', floor(n / bits_needed_256));

% Qualification verdict
fprintf('  Qualification Verdict:\n');
if H_min >= 0.9
    fprintf('  ✓ EXCELLENT  — H_min >= 0.9. Bitstream is high quality.\n');
    fprintf('                 Proceed directly to SHA-256.\n');
elseif H_min >= 0.5
    fprintf('  ⚠ ACCEPTABLE — H_min >= 0.5. Proceed with SHA-256 but\n');
    fprintf('                 collect %d bits per 256-bit output call.\n', bits_needed_256);
elseif H_min >= 0.2
    fprintf('  ✗ MARGINAL   — H_min < 0.5. Apply Von Neumann whitening\n');
    fprintf('                 first, then re-estimate entropy.\n');
else
    fprintf('  ✗ POOR       — H_min < 0.2. Revisit digitisation method.\n');
    fprintf('                 The chaotic signal may not be in steady state.\n');
end
fprintf('=================================================================\n');

%% ── VISUALISATION ────────────────────────────────────────────────────────

figure('Name','SP 800-90B Entropy Estimates','Color','w','Position',[80 80 1100 700]);

% -- Subplot 1: Entropy bar chart per estimator
subplot(2,2,[1 2]);
valid_vals  = entropy_values(valid_mask);
valid_names = estimator_names(valid_mask);
bar_cols    = zeros(length(valid_vals), 3);
for i = 1:length(valid_vals)
    if valid_vals(i) >= 0.9,     bar_cols(i,:) = [0.2 0.7 0.3];   % green
    elseif valid_vals(i) >= 0.5, bar_cols(i,:) = [0.9 0.7 0.1];   % yellow
    else,                        bar_cols(i,:) = [0.85 0.2 0.2];   % red
    end
end
b2 = bar(valid_vals, 'FaceColor', 'flat');
b2.CData = bar_cols;
hold on;
yline(0.9, 'g--', 'LineWidth', 1.5, 'Label', 'Excellent (0.9)', ...
      'LabelHorizontalAlignment','left');
yline(0.5, 'y--', 'LineWidth', 1.5, 'Label', 'Acceptable (0.5)', ...
      'LabelHorizontalAlignment','left');
xticks(1:length(valid_names)); xticklabels(valid_names); xtickangle(15);
ylabel('Entropy (bits/bit)'); ylim([0 1.1]);
title('SP 800-90B Entropy Estimates per Estimator');
grid on; box on;

% -- Subplot 2: Markov transition heatmap
subplot(2,2,3);
imagesc(P_trans);
colormap(gca, 'hot');
colorbar;
xticks([1 2]); xticklabels({'→0','→1'});
yticks([1 2]); yticklabels({'From 0','From 1'});
title('Markov Transition Probabilities');
for r = 1:2
    for c = 1:2
        text(c, r, sprintf('%.3f', P_trans(r,c)), ...
             'HorizontalAlignment','center','Color','cyan','FontWeight','bold');
    end
end

% -- Subplot 3: Lag prediction accuracy vs lag
subplot(2,2,4);
lag_accs = zeros(1, max_lag);
for k = 1:max_lag
    x_lag  = bits(1:end-k);
    y_curr = bits(k+1:end);
    n_from_0 = sum(x_lag == 0);
    n_from_1 = sum(x_lag == 1);
    c0 = max(sum(y_curr(x_lag==0)==0), sum(y_curr(x_lag==0)==1));
    c1 = max(sum(y_curr(x_lag==1)==0), sum(y_curr(x_lag==1)==1));
    lag_accs(k) = (c0+c1)/length(y_curr);
end
plot(1:max_lag, lag_accs, 'bo-', 'LineWidth', 1.5, 'MarkerFaceColor','b');
hold on;
yline(0.5, 'r--', 'Label', 'Random baseline (0.5)', ...
      'LabelHorizontalAlignment','left');
xlabel('Lag k'); ylabel('Prediction Accuracy');
title('Lag Prediction Accuracy vs Lag');
ylim([0.4 1.0]); grid on; box on;

sgtitle('NIST SP 800-90B Entropy Estimation Report', ...
        'FontSize', 14, 'FontWeight', 'bold');

fprintf('\nDone.\n');

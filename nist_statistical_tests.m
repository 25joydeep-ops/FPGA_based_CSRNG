% =========================================================================
% NIST SP 800-22 Statistical Tests for Chaotic Bitstream
% =========================================================================
% Runs 7 statistical tests on the Method B (12-bit ADS1015) bitstream.
% Each test produces a p-value. A p-value >= 0.01 means the sequence
% passes that test (cannot be distinguished from random at 99% confidence).
%
% Tests included:
%   1. Frequency (Monobit) Test
%   2. Frequency Test within Blocks
%   3. Runs Test
%   4. Longest Run of Ones Test
%   5. Serial Test
%   6. Approximate Entropy Test
%   7. Autocorrelation Test
% =========================================================================

clc; clear; close all;

%% ── 1. LOAD BITSTREAM ────────────────────────────────────────────────────

filename = 'SHA256_output3_h.txt';

fid      = fopen(filename, 'r');
raw      = fread(fid, '*char')';
fclose(fid);

% Convert character string '010110...' to numeric array of 0s and 1s
bits = double(raw == '1');
n    = length(bits);

fprintf('=================================================================\n');
fprintf('         NIST SP 800-22 Statistical Test Suite\n');
fprintf('=================================================================\n');
fprintf('  Bitstream  : %s\n', filename);
fprintf('  Total bits : %d\n', n);
fprintf('  Ones       : %d  (%.2f%%)\n', sum(bits), 100*sum(bits)/n);
fprintf('  Zeros      : %d  (%.2f%%)\n', sum(~bits), 100*sum(~bits)/n);
fprintf('=================================================================\n\n');

% Significance level
alpha = 0.01;   % 99% confidence — NIST standard threshold

% Results storage
test_names = {};
p_values   = [];
pass_fail  = {};

%% ── TEST 1: FREQUENCY (MONOBIT) TEST ─────────────────────────────────────
% Checks if the number of 1s and 0s are approximately equal.
% A biased source (more 1s or more 0s) will fail this.
%
% H0: The proportion of ones is 0.5 (perfectly balanced)

S_n  = sum(2*bits - 1);          % convert bits to +1/-1 and sum
s_obs = abs(S_n) / sqrt(n);
p1    = erfc(s_obs / sqrt(2));

test_names{end+1} = 'Frequency (Monobit)';
p_values(end+1)   = p1;
pass_fail{end+1}  = result_str(p1, alpha);

fprintf('── Test 1: Frequency (Monobit) ──────────────────────────────────\n');
fprintf('  S_n = %d | s_obs = %.4f | p-value = %.6f | %s\n\n', ...
        S_n, s_obs, p1, pass_fail{end});

%% ── TEST 2: FREQUENCY TEST WITHIN BLOCKS ─────────────────────────────────
% Divides the bitstream into M-bit blocks and tests if each block
% has a proportion of ones close to 0.5.
% Catches local bias that averages out globally.
%
% H0: Each block has equal proportions of 0s and 1s

M        = 8;                          % block size in bits
N_blocks = floor(n / M);              % number of complete blocks
chi_sq   = 0;

for i = 1:N_blocks
    block    = bits((i-1)*M + 1 : i*M);
    pi_i     = sum(block) / M;
    chi_sq   = chi_sq + (pi_i - 0.5)^2;
end
chi_sq = 4 * M * chi_sq;
p2     = 1 - gammainc(chi_sq/2, N_blocks/2, 'lower');   % chi-squared p-value

test_names{end+1} = 'Frequency within Blocks';
p_values(end+1)   = p2;
pass_fail{end+1}  = result_str(p2, alpha);

fprintf('── Test 2: Frequency within Blocks ──────────────────────────────\n');
fprintf('  Block size M=%d | Blocks=%d | chi²=%.4f | p-value=%.6f | %s\n\n', ...
        M, N_blocks, chi_sq, p2, pass_fail{end});

%% ── TEST 3: RUNS TEST ────────────────────────────────────────────────────
% A run is an unbroken sequence of identical bits.
% Tests whether the number of runs (transitions between 0 and 1)
% is consistent with a random sequence.
% Catches sources that switch too fast (high frequency) or too slow
% (long stretches of same bit) — both are chaotic circuit failure modes.
%
% H0: The number of runs is consistent with random

pi_hat = sum(bits) / n;              % proportion of ones

% Pre-test: if |pi_hat - 0.5| >= 2/sqrt(n), test is not applicable
if abs(pi_hat - 0.5) >= (2 / sqrt(n))
    p3 = NaN;
    fprintf('── Test 3: Runs Test ─────────────────────────────────────────────\n');
    fprintf('  Pre-test FAILED: pi_hat=%.4f too far from 0.5. Test not applicable.\n\n', pi_hat);
else
    V_n = 1 + sum(bits(1:end-1) ~= bits(2:end));   % number of runs
    num = abs(V_n - 2*n*pi_hat*(1-pi_hat));
    den = 2 * sqrt(2*n) * pi_hat * (1-pi_hat);
    p3  = erfc(num / den);

    fprintf('── Test 3: Runs Test ─────────────────────────────────────────────\n');
    fprintf('  pi_hat=%.4f | Runs V_n=%d | p-value=%.6f | %s\n\n', ...
            pi_hat, V_n, p3, result_str(p3, alpha));
end

test_names{end+1} = 'Runs Test';
p_values(end+1)   = p3;
pass_fail{end+1}  = result_str(p3, alpha);

%% ── TEST 4: LONGEST RUN OF ONES TEST ─────────────────────────────────────
% Tests whether the longest run of consecutive 1s is consistent
% with what a random sequence would produce.
% Flags chaotic circuits that get "stuck" near one threshold side.
%
% H0: The longest run of ones is consistent with random

% NIST SP 800-22 Section 2.4 exact block sizes, boundaries and probabilities
% v_lower(k) and v_upper(k) define the inclusive range for category k.
% Last category is always ">= v_lower(end)" (open upper bound).

if n < 128
    error('Need at least 128 bits for Longest Run test.');
elseif n < 6272
    % M=8: categories are <=1, =2, =3, >=4
    M_lr    = 8;
    K       = 3;        % degrees of freedom = number of categories - 1
    N_lr    = floor(n / M_lr);
    % Exact boundaries per NIST SP 800-22 Table 2.4.4
    v_lower = [1, 2, 3, 4];   % lower bound of each category (inclusive)
    v_upper = [1, 2, 3, inf]; % upper bound (inf = open, catches all >= v_lower)
    pi_lr   = [0.2148, 0.3672, 0.2305, 0.1875];

elseif n < 750000
    % M=128: categories are <=4, =5, =6, =7, =8, >=9
    M_lr    = 128;
    K       = 5;
    N_lr    = floor(n / M_lr);
    v_lower = [4,  5,  6,  7,  8,  9];
    v_upper = [4,  5,  6,  7,  8,  inf];
    pi_lr   = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124];

else
    % M=10000: categories are <=10,=11,=12,=13,=14,=15,>=16
    M_lr    = 10000;
    K       = 6;
    N_lr    = floor(n / M_lr);
    v_lower = [10, 11, 12, 13, 14, 15, 16];
    v_upper = [10, 11, 12, 13, 14, 15, inf];
    pi_lr   = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727];
end

n_cats = length(pi_lr);   % total number of categories

% Count longest run of ones in each block
freq = zeros(1, n_cats);
for i = 1:N_lr
    block   = bits((i-1)*M_lr + 1 : i*M_lr);
    max_run = 0;
    cur_run = 0;
    for j = 1:M_lr
        if block(j) == 1
            cur_run = cur_run + 1;
            max_run = max(max_run, cur_run);
        else
            cur_run = 0;
        end
    end

    % Bin into correct category using exact NIST boundaries
    binned = false;
    for k = 1:n_cats
        if isinf(v_upper(k))
            % Last category: longest run >= v_lower(k)
            if max_run >= v_lower(k)
                freq(k) = freq(k) + 1;
                binned = true;
            end
        else
            % Middle categories: exact match within [v_lower(k), v_upper(k)]
            if max_run >= v_lower(k) && max_run <= v_upper(k)
                freq(k) = freq(k) + 1;
                binned = true;
            end
        end
        if binned, break; end
    end

    % If max_run is below the first category lower bound, put in first bin
    if ~binned
        freq(1) = freq(1) + 1;
    end
end

chi_lr = sum((freq - N_lr * pi_lr).^2 ./ (N_lr * pi_lr));
p4     = 1 - gammainc(chi_lr/2, K/2, 'lower');

test_names{end+1} = 'Longest Run of Ones';
p_values(end+1)   = p4;
pass_fail{end+1}  = result_str(p4, alpha);

fprintf('── Test 4: Longest Run of Ones ───────────────────────────────────\n');
fprintf('  Block size M=%d | Blocks=%d | Categories=%d\n', M_lr, N_lr, n_cats);
fprintf('  Observed freq : %s\n', num2str(freq));
fprintf('  Expected freq : %s\n', num2str(round(N_lr * pi_lr, 1)));
fprintf('  chi²=%.4f | p-value=%.6f | %s\n\n', chi_lr, p4, pass_fail{end});

%% ── TEST 5: SERIAL TEST ──────────────────────────────────────────────────
% Checks whether all possible m-bit patterns appear with equal frequency.
% Tests for short-range correlations between consecutive bits — directly
% sensitive to temporal structure in chaotic signals.
%
% H0: All m-bit overlapping patterns are equally frequent

m = 3;   % pattern length (typically 2 or 3 for sequences < 10000 bits)

psi_sq = @(seq, len, pat_len) compute_psi_sq(seq, len, pat_len);

psi_m   = psi_sq(bits, n, m);
psi_m1  = psi_sq(bits, n, m-1);
psi_m2  = psi_sq(bits, n, m-2);

delta1  = psi_m  - psi_m1;
delta2  = psi_m  - 2*psi_m1 + psi_m2;

p5a = 1 - gammainc(delta1/2, 2^(m-2), 'lower');
p5b = 1 - gammainc(delta2/2, 2^(m-3), 'lower');

test_names{end+1} = 'Serial Test (p1)';
p_values(end+1)   = p5a;
pass_fail{end+1}  = result_str(p5a, alpha);

test_names{end+1} = 'Serial Test (p2)';
p_values(end+1)   = p5b;
pass_fail{end+1}  = result_str(p5b, alpha);

fprintf('── Test 5: Serial Test (m=%d) ────────────────────────────────────\n', m);
fprintf('  ψ²(m)=%.4f | ψ²(m-1)=%.4f | ψ²(m-2)=%.4f\n', psi_m, psi_m1, psi_m2);
fprintf('  Δ1=%.4f | p1=%.6f | %s\n', delta1, p5a, result_str(p5a, alpha));
fprintf('  Δ2=%.4f | p2=%.6f | %s\n\n', delta2, p5b, result_str(p5b, alpha));

%% ── TEST 6: APPROXIMATE ENTROPY TEST ─────────────────────────────────────
% Compares the frequency of overlapping m-bit patterns vs (m+1)-bit patterns.
% Measures how predictable the next bit is given recent history.
% Closest NIST SP 800-22 test to directly measuring entropy — cross-checks
% the entropy estimators in the Stage 1 script.
%
% H0: The sequence is random (high approximate entropy)

m_ae  = 2;   % template length — keep small for sequences < 10000 bits

phi_m  = compute_phi(bits, n, m_ae);
phi_m1 = compute_phi(bits, n, m_ae + 1);

ApEn   = phi_m - phi_m1;
chi_ae = 2 * n * (log(2) - ApEn);
p6     = 1 - gammainc(chi_ae/2, 2^(m_ae-1), 'lower');

test_names{end+1} = 'Approximate Entropy';
p_values(end+1)   = p6;
pass_fail{end+1}  = result_str(p6, alpha);

fprintf('── Test 6: Approximate Entropy (m=%d) ────────────────────────────\n', m_ae);
fprintf('  φ(m)=%.6f | φ(m+1)=%.6f | ApEn=%.6f\n', phi_m, phi_m1, ApEn);
fprintf('  chi²=%.4f | p-value=%.6f | %s\n\n', chi_ae, p6, pass_fail{end});

%% ── TEST 7: AUTOCORRELATION TEST ─────────────────────────────────────────
% Computes correlation between the bitstream and a version of itself
% shifted by d positions. A truly random source has near-zero
% autocorrelation at all lags.
% Most direct test for temporal structure that chaotic circuits produce.
%
% H0: There is no autocorrelation at lag d

lags_to_test = [1 2 3 4 5 8 10];   % test multiple lags
fprintf('── Test 7: Autocorrelation Test ─────────────────────────────────\n');

ac_p_values = zeros(1, length(lags_to_test));
for idx = 1:length(lags_to_test)
    d      = lags_to_test(idx);
    A_d    = sum(xor(bits(1:end-d), bits(d+1:end)));
    z_d    = (2*A_d - (n-d)) / sqrt(n-d);
    p7_d   = erfc(abs(z_d) / sqrt(2));
    ac_p_values(idx) = p7_d;
    res    = result_str(p7_d, alpha);
    fprintf('  Lag d=%-3d | A(d)=%d | z=%.4f | p-value=%.6f | %s\n', ...
            d, A_d, z_d, p7_d, res);
end

% Use minimum p-value across lags as the reported result (most conservative)
[p7, worst_lag_idx] = min(ac_p_values);
test_names{end+1} = sprintf('Autocorrelation (worst lag=%d)', lags_to_test(worst_lag_idx));
p_values(end+1)   = p7;
pass_fail{end+1}  = result_str(p7, alpha);
fprintf('  → Reporting worst-case lag d=%d | p=%.6f | %s\n\n', ...
        lags_to_test(worst_lag_idx), p7, pass_fail{end});

%% ── SUMMARY REPORT ───────────────────────────────────────────────────────

fprintf('=================================================================\n');
fprintf('                    FINAL RESULTS SUMMARY\n');
fprintf('=================================================================\n');
fprintf('  %-35s  %-10s  %s\n', 'Test', 'p-value', 'Result');
fprintf('  %s\n', repmat('-', 1, 60));

n_pass = 0; n_fail = 0; n_na = 0;
for i = 1:length(test_names)
    if isnan(p_values(i))
        fprintf('  %-35s  %-10s  %s\n', test_names{i}, 'N/A', 'NOT APPLICABLE');
        n_na = n_na + 1;
    else
        fprintf('  %-35s  %-10.6f  %s\n', test_names{i}, p_values(i), pass_fail{i});
        if strcmp(pass_fail{i}, 'PASS'), n_pass = n_pass + 1;
        else,                            n_fail = n_fail + 1; end
    end
end

fprintf('  %s\n', repmat('-', 1, 60));
fprintf('  Tests passed : %d / %d\n', n_pass, n_pass + n_fail);
if n_na > 0
    fprintf('  Not applicable: %d\n', n_na);
end
fprintf('\n');

if n_fail == 0
    fprintf('  OVERALL: PASS — Bitstream shows no detectable non-random structure.\n');
    fprintf('           Safe to proceed to entropy estimation and SHA-256.\n');
else
    fprintf('  OVERALL: FAIL — %d test(s) failed. Review individual results.\n', n_fail);
    fprintf('           Consider applying Von Neumann whitening before SHA-256.\n');
end
fprintf('=================================================================\n');

%% ── VISUALISATION ────────────────────────────────────────────────────────

valid_idx = ~isnan(p_values);
p_plot    = p_values(valid_idx);
n_plot    = names_valid(test_names, valid_idx);

figure('Name','NIST SP 800-22 Results','Color','w','Position',[80 80 1000 500]);
bar_colors = zeros(length(p_plot), 3);
for i = 1:length(p_plot)
    if p_plot(i) >= alpha
        bar_colors(i,:) = [0.2 0.7 0.3];   % green = pass
    else
        bar_colors(i,:) = [0.85 0.2 0.2];  % red = fail
    end
end

b = bar(p_plot, 'FaceColor', 'flat');
b.CData = bar_colors;
hold on;
yline(alpha, 'r--', 'LineWidth', 2, 'Label', sprintf('α = %.2f (threshold)', alpha), ...
      'LabelHorizontalAlignment', 'left');
xticks(1:length(p_plot));
xticklabels(n_plot);
xtickangle(25);
ylabel('p-value');
title('NIST SP 800-22 Test Results — p-values (green = PASS, red = FAIL)');
ylim([0 1]);
grid on; box on;

%% ── HELPER FUNCTIONS ─────────────────────────────────────────────────────

function s = result_str(p, alpha)
    if isnan(p),       s = 'N/A';
    elseif p >= alpha, s = 'PASS';
    else,              s = 'FAIL';
    end
end

function psi = compute_psi_sq(bits, n, m)
    if m == 0, psi = 0; return; end
    counts = zeros(1, 2^m);
    extended = [bits, bits(1:m-1)];   % wrap around
    for i = 1:n
        pattern = extended(i:i+m-1);
        idx = bi2de(pattern, 'left-msb') + 1;
        counts(idx) = counts(idx) + 1;
    end
    psi = (2^m / n) * sum(counts.^2) - n;
end

function phi = compute_phi(bits, n, m)
    extended = [bits, bits(1:m-1)];
    counts   = zeros(1, 2^m);
    for i = 1:n
        pattern = extended(i:i+m-1);
        idx = bi2de(pattern, 'left-msb') + 1;
        counts(idx) = counts(idx) + 1;
    end
    counts = counts(counts > 0);
    phi    = sum((counts/n) .* log(counts/n));
end

function names_out = names_valid(names_in, valid_idx)
    names_out = {};
    idx_arr   = find(valid_idx);
    for i = 1:length(idx_arr)
        names_out{end+1} = names_in{idx_arr(i)};
    end
end

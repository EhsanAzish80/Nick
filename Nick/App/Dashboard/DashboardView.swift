import SwiftUI

struct DashboardView: View {

    @EnvironmentObject private var correlator: ThreatCorrelator
    @EnvironmentObject private var auditor: SystemAuditor

    var body: some View {
        VStack(spacing: 0) {
            headerBar
            Divider()
            threatScoreSection
            Spacer()
        }
        .frame(width: 360)
        .background(.background)
    }

    // MARK: - Sections

    private var headerBar: some View {
        HStack {
            Image(systemName: "shield.fill")
                .foregroundStyle(.blue)
            Text("Nick")
                .font(.headline)
            Spacer()
            Text("v0.1")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal)
        .padding(.vertical, 10)
    }

    private var threatScoreSection: some View {
        VStack(spacing: 8) {
            Text("Threat Score")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Text(String(format: "%.0f%%", correlator.overallScore * 100))
                .font(.system(size: 48, weight: .bold, design: .rounded))
                .foregroundStyle(scoreColor)
        }
        .padding()
    }

    private var scoreColor: Color {
        switch correlator.overallScore {
        case 0..<0.25: return .green
        case 0.25..<0.5: return .yellow
        case 0.5..<0.75: return .orange
        default: return .red
        }
    }
}

#Preview {
    DashboardView()
        .environmentObject(ThreatCorrelator())
        .environmentObject(SystemAuditor())
}

import warnings

# PyG imports trigger a torch.jit deprecation warning on recent torch; not actionable here.
warnings.filterwarnings("ignore", message=".*torch.jit.script.*", category=FutureWarning)
